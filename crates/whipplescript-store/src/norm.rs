//! Authenticated norm-ledger events (DR-0098, V0).
//!
//! C0 is immutable in this slice. Every event pins its genesis/charter and exact
//! vocabulary. This module verifies and interprets events; host stores own the
//! atomic transaction that checks the persisted pin and appends the result.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_core::vocabulary::{
    AdmissionPredicate, Arbitration, ReferenceForm, ValueType, Vocabulary, VocabularyDefinition,
    VocabularyRef, VocabularyRegistry, Witness, WitnessSide,
};

use crate::norm_correspondence::CorrespondenceDeclaration;
use crate::norm_manifests::ManifestDeclaration;
use crate::norm_relations::{
    RelationCardinality, RelationDeclaration, RelationEdge, RelationFamilyView,
};

use crate::items::{event_content_id, TrackerEvent};
use crate::{StoreError, StoreResult};

pub const NORM_SCHEMA_SQL: &str = include_str!("norm_schema.sql");

/// One statement admits a validated batch on either host. JSON table input
/// avoids a per-event bind-variable limit, without splitting atomic admission.
pub const NORM_INSERT_SQL: &str = "INSERT OR IGNORE INTO tracker_events (event_id, parents_json, issue_id, kind, payload_json, actor, effect_id, created_at) SELECT json_extract(value, '$.event_id'), json_extract(value, '$.parents'), json_extract(value, '$.issue_id'), json_extract(value, '$.kind'), json_extract(value, '$.payload_json'), json_extract(value, '$.actor'), ?2, json_extract(value, '$.created_at') FROM json_each(?1)";

pub const BOOTSTRAP_KIND: &str = "norm.governance.bootstrapped";
pub const CREATE_KIND: &str = "norm.record.created";
pub const TRANSITION_KIND: &str = "norm.record.transitioned";
pub const ROTATE_KIND: &str = "norm.governance.rotated";
pub const RETIRE_KIND: &str = "norm.record.retired";
pub const EDIT_KIND: &str = "norm.record.edited";
pub const ACTIVATE_KIND: &str = "norm.governance.activated";

/// A signature verifier is supplied by the authenticated embedding boundary.
/// It must verify both the cryptographic signature and the principal/key binding.
/// A key chosen by the event is never sufficient evidence of that binding.
pub trait NormVerifier {
    fn verify(
        &self,
        actor: &NormActor,
        signing_bytes: &[u8],
        signature: &str,
    ) -> Result<(), String>;
    /// Permission for this executor to create a ledger for the represented owner.
    /// This is independent of the executor possessing a signing key.
    fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String>;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormActor {
    pub principal: String,
    pub algorithm: String,
    pub key_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionEffect {
    Activate,
    Retire,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivenessRule {
    pub status: String,
    pub effect: RevisionEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormVocabulary {
    pub definition: VocabularyDefinition,
    /// Creation is explicit too: no omitted-policy public default.
    pub creation: AdmissionPredicate,
    /// Omission makes fields immutable, not implicitly public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editing: Option<AdmissionPredicate>,
    /// None means no interpretation was declared, not that no revision binds.
    /// This is pinned in C0 alongside creation/editing policy, never guessed
    /// from a status spelling or substituted from newer bundled defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effectiveness: Option<Vec<EffectivenessRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_role: Option<crate::norm_inventory::InventoryRole>,
    /// Declares this vocabulary's records as edges of a relation family
    /// (DR-0122). None means records of this vocabulary relate nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationDeclaration>,
    /// Declares this vocabulary's records as manifests (DR-0122): members and
    /// a completeness claim. None means records of this vocabulary select nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestDeclaration>,
    /// Declares this vocabulary's records as correspondences (DR-0122): exact
    /// revisions on two sides and a claim from a closed set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correspondence: Option<CorrespondenceDeclaration>,
    /// Declares this vocabulary's records as typed constraints on
    /// requirements (norm-plane §11.1). None means they constrain nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<crate::norm_constraints::ConstraintDeclaration>,
    /// Declares entering one status a deployment of the cuts a field lists,
    /// which a host admits only where they are supported (norm-plane §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<crate::norm_deployment::DeploymentDeclaration>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormCharter {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::norm_resources::decode_domains"
    )]
    pub resource_domains: Option<BTreeMap<String, crate::norm_resources::ResourceDomain>>,
    pub vocabularies: Vec<NormVocabulary>,
    /// Exact, versioned meanings for typed reference fields. Missing entries
    /// remain unknown to dependency coverage; structural roles imply none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_classes: Vec<crate::norm_reference_inventory::NormReferenceClass>,
    /// Named scopes delegated to the authenticated governance owner by C0.
    pub owner_scopes: Vec<String>,
    /// Who may activate a successor charter (norm-plane §10). Omission means
    /// this charter is never replaced, not that anyone may replace it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<AdmissionPredicate>,
    /// Stream lines gated like the mainline (norm-plane §5), a release line
    /// say. The mainline is always gated and is not named here. A host leases
    /// each one to the gate when the act declaring it is admitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gated_refs: Vec<String>,
    /// The canonicalizer version pinned for each file class, the way a
    /// toolchain is pinned (norm-plane §9). A requirement subject naming a
    /// declaration resolves only through its class's pinned version, so a
    /// grammar or normalizer bump re-keys through an activation that
    /// re-pins it.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::norm_resources::decode_pins"
    )]
    pub canonicalizers: BTreeMap<String, String>,
}

impl NormCharter {
    /// Bundled declarations use exactly the same validation and admission path
    /// as caller-authored data. Loading them does not install a charter.
    pub fn bundled() -> StoreResult<Self> {
        let charter: Self = serde_json::from_str(include_str!("norm_defaults.json"))?;
        registry_for(&charter)?;
        Ok(charter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "act", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormAct {
    Bootstrap {
        creator: String,
        charter: NormCharter,
    },
    Create {
        ledger: String,
        /// Omission pins genesis, never a moving latest-root default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        vocabulary: VocabularyRef,
        fields_json: String,
    },
    Transition {
        ledger: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        vocabulary: VocabularyRef,
        record: String,
        previous: String,
        status: String,
    },
    Edit {
        ledger: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        vocabulary: VocabularyRef,
        record: String,
        previous: String,
        fields_json: String,
    },
    /// Retire the exact active acceptance, including when latest content is a draft.
    Retire {
        ledger: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority: Option<String>,
        vocabulary: VocabularyRef,
        record: String,
        previous: String,
        revision: String,
        activation: String,
        status: String,
    },
    Rotate {
        ledger: String,
        previous: String,
        successor: NormActor,
        frontier: Vec<String>,
    },
    /// Install a successor charter under the preceding charter's activation
    /// rule (norm-plane §10, W1). Like a rotation it closes the exact frontier
    /// and begins an authority epoch, so every later act descends from it.
    Activate {
        ledger: String,
        previous: String,
        charter: NormCharter,
        migration: Vec<crate::norm_activation::VocabularyMigration>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        changes: Vec<crate::norm_activation::AuthorizedChange>,
        frontier: Vec<String>,
    },
}

/// What an act bound at validation. Every premise is also a causal parent of
/// the act's event, so a replay applies the act after the events it was
/// validated against and reproduces the admission. The door refuses the act
/// when a bound premise no longer holds; a caller re-captures and validates
/// again rather than substituting a newer token into an old calculation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormPremises {
    /// The basis of the relation family the act's edge joins: the event id of
    /// the family's last admitted act, or the ledger's genesis when it has none.
    /// Any act on a record of the family moves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_basis: Option<String>,
    /// The content ids the act's reference fields name, so the records and
    /// revisions they resolve to precede the act in every replay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// The ledger frontier an exhaustive manifest claim was judged against.
    /// Bound as parents, so the inventory at that frontier precedes the act,
    /// and the judgment is derived there in every replay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inventory_frontier: Vec<String>,
}

/// The nonce identifies one invocation by this principal. Retries reuse the
/// signed event; a second event reusing a nonce for different bytes is refused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormStatement {
    pub protocol: String,
    pub actor: NormActor,
    pub nonce: String,
    pub created_at: String,
    pub action: NormAct,
    /// The premises this act was validated against (DR-0122 §13.4). Absent
    /// premises are not serialized, so earlier statements keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub premises: Option<NormPremises>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedNormEvent {
    pub statement: NormStatement,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_signature: Option<String>,
}

/// Trusted destination state. The authority event commits to the frontier it
/// closes; this is never a caller-provided latest-key label from an import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormCheckpoint {
    pub ledger: String,
    pub authority_head: String,
}

impl NormCheckpoint {
    pub fn genesis(ledger: String) -> Self {
        Self {
            authority_head: ledger.clone(),
            ledger,
        }
    }

    pub fn validate(&self) -> StoreResult<()> {
        if [&self.ledger, &self.authority_head]
            .iter()
            .any(|id| id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(refused("norm checkpoint must contain SHA-256 event ids"));
        }
        Ok(())
    }
}

impl NormStatement {
    pub fn signing_bytes(&self) -> StoreResult<Vec<u8>> {
        let mut bytes = b"whipplescript.norm.event.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }
}

impl SignedNormEvent {
    /// Authenticate the existing signed-event codec without granting admission.
    pub fn authenticate(&self, verifier: &dyn NormVerifier) -> StoreResult<()> {
        verify_event(&self.tracker_event()?, verifier).map(|_| ())
    }

    /// Transport metadata is derived from the signed statement, never supplied
    /// separately by a caller. The tracker content hash commits to the signature
    /// as well as the statement; a retry must reuse its signed envelope.
    pub fn tracker_event(&self) -> StoreResult<TrackerEvent> {
        let (kind, issue_id, mut parents) = match &self.statement.action {
            NormAct::Bootstrap { .. } => (BOOTSTRAP_KIND, None, vec![]),
            NormAct::Create {
                ledger, authority, ..
            } => (
                CREATE_KIND,
                None,
                vec![ledger.clone(), authority.as_ref().unwrap_or(ledger).clone()],
            ),
            NormAct::Transition {
                ledger,
                authority,
                record,
                previous,
                ..
            } => (
                TRANSITION_KIND,
                Some(record.clone()),
                vec![
                    ledger.clone(),
                    previous.clone(),
                    authority.as_ref().unwrap_or(ledger).clone(),
                ],
            ),
            NormAct::Edit {
                ledger,
                authority,
                record,
                previous,
                ..
            } => (
                EDIT_KIND,
                Some(record.clone()),
                vec![
                    ledger.clone(),
                    previous.clone(),
                    authority.as_ref().unwrap_or(ledger).clone(),
                ],
            ),
            NormAct::Retire {
                ledger,
                authority,
                record,
                previous,
                revision,
                activation,
                ..
            } => (
                RETIRE_KIND,
                Some(record.clone()),
                vec![
                    ledger.clone(),
                    previous.clone(),
                    revision.clone(),
                    activation.clone(),
                    authority.as_ref().unwrap_or(ledger).clone(),
                ],
            ),
            NormAct::Rotate {
                ledger,
                previous,
                frontier,
                ..
            } => {
                let mut parents = frontier.clone();
                parents.extend([ledger.clone(), previous.clone()]);
                (ROTATE_KIND, None, parents)
            }
            NormAct::Activate {
                ledger,
                previous,
                frontier,
                ..
            } => {
                let mut parents = frontier.clone();
                parents.extend([ledger.clone(), previous.clone()]);
                (ACTIVATE_KIND, None, parents)
            }
        };
        if let Some(premises) = &self.statement.premises {
            parents.extend(premises.family_basis.iter().cloned());
            parents.extend(premises.references.iter().cloned());
            parents.extend(premises.inventory_frontier.iter().cloned());
        }
        parents.sort();
        parents.dedup();
        let payload_json = serde_json::to_string(self)?;
        let actor = Some(self.statement.actor.principal.clone());
        let created_at = self.statement.created_at.clone();
        let event_id = event_content_id(
            kind,
            issue_id.as_deref(),
            &payload_json,
            actor.as_deref(),
            &parents,
            &created_at,
        );
        Ok(TrackerEvent {
            event_id,
            parents,
            issue_id,
            kind: kind.into(),
            payload_json,
            actor,
            created_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormRecord {
    pub id: String,
    pub vocabulary: VocabularyRef,
    pub fields: serde_json::Value,
    /// The immutable event that established these fields. Lifecycle/no-op
    /// events move `head` without silently replacing this content revision.
    pub content_head: String,
    pub status: String,
    pub head: String,
}

/// An active value is the exact snapshot at its activating event. Its head
/// identifies that act even when later drafts/no-op edits move the current head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectiveRevision {
    Unspecified,
    Inactive,
    Active {
        record: Box<NormRecord>,
        lifecycle: EffectiveLifecycle,
    },
}

/// Latest admitted lifecycle of the effective content; draft edits do not move it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveLifecycle {
    pub status: String,
    pub head: String,
}

/// Derived state, never a substitute for the append-only signed event history.
#[derive(Clone, Debug)]
pub struct NormView {
    pub ledger: String,
    pub owner: NormActor,
    pub charter: NormCharter,
    pub records: BTreeMap<String, NormRecord>,
    pub effective_records: BTreeMap<String, NormRecord>,
    pub(crate) effective_lifecycles: BTreeMap<String, EffectiveLifecycle>,
    /// Every content revision ever admitted, by its revision id: the record as
    /// it stood at that act, so a revision reference resolves to its record
    /// after later edits moved the head and a view can render exact content.
    revisions: BTreeMap<String, NormRecord>,
    /// The last admitted act on any record of each relation family; the basis
    /// a relation act binds. A family with no act yet has the ledger as its basis.
    family_heads: BTreeMap<String, String>,
    /// Every admitted act's causal parents, so an admission rule that reads
    /// ledger state judges it as the act's causal past saw it — the same in
    /// every replay order.
    event_parents: BTreeMap<String, Vec<String>>,
    /// Each record's state, and its effective revision, after each of its
    /// acts in admission order.
    record_acts: BTreeMap<String, Vec<RecordAct>>,
    /// The inventory frontier each exhaustive manifest revision bound.
    manifest_bases: BTreeMap<String, Vec<String>>,
    pub authority_head: String,
    pub frontier: BTreeSet<String>,
    /// Genesis and every admitted activation, in replay order. The current
    /// charter's fields do not cover records accepted in earlier epochs.
    pub(crate) charter_events: Vec<String>,
    /// Every admitted vocabulary version's reference meanings, including
    /// versions with no declared classes. Reintroduction cannot change them.
    pub(crate) reference_meaning_history: BTreeMap<
        (String, String),
        BTreeMap<String, crate::norm_reference_inventory::NormReferenceMeaning>,
    >,
    authority_history: BTreeSet<String>,
    event_order: Vec<String>,
    creator: String,
    /// Every vocabulary any charter of this ledger declared: the charter in
    /// force's, and each earlier one's, which still interprets its records.
    pub(crate) registry: VocabularyRegistry,
    /// Declarations of earlier charters no longer in force, by which their
    /// closed and retired records stay interpreted and replayable.
    pub(crate) historical: Vec<NormVocabulary>,
    /// Records an activation retired: closed under the preceding charter's
    /// authority, and admitting no act again.
    pub(crate) retired: BTreeSet<String>,
    nonces: BTreeMap<(String, String), String>,
}

fn refused(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

fn validate_statement_metadata(statement: &NormStatement) -> StoreResult<()> {
    if statement.protocol != "whipplescript.norm/v1"
        || statement.nonce.trim().is_empty()
        || statement.actor.principal.trim().is_empty()
        || statement.actor.key_id.trim().is_empty()
        || statement.actor.algorithm.trim().is_empty()
        || statement.created_at.trim().is_empty()
    {
        return Err(refused(
            "norm event needs protocol v1, authenticated actor, nonce and creation time",
        ));
    }
    Ok(())
}

fn verify_event(event: &TrackerEvent, verifier: &dyn NormVerifier) -> StoreResult<SignedNormEvent> {
    let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
    if signed.tracker_event()? != *event {
        return Err(refused(
            "norm event metadata or content hash differs from its signed statement",
        ));
    }
    let statement = &signed.statement;
    validate_statement_metadata(statement)?;
    verifier
        .verify(
            &statement.actor,
            &statement.signing_bytes()?,
            &signed.signature,
        )
        .map_err(refused)?;
    match (&statement.action, &signed.successor_signature) {
        (NormAct::Rotate { successor, .. }, Some(signature)) => {
            verifier
                .verify(successor, &statement.signing_bytes()?, signature)
                .map_err(refused)?;
        }
        (NormAct::Rotate { .. }, None) | (_, Some(_)) => {
            // MUTATION-SUCCESS-EXPR: Ok(signed)
            return Err(refused("rotation alone requires a successor signature"));
        }
        (_, None) => {}
    }
    Ok(signed)
}

pub(crate) fn registry_for(charter: &NormCharter) -> StoreResult<VocabularyRegistry> {
    crate::norm_resources::validate_resource_domains(charter)?;
    crate::norm_resources::validate_canonicalizer_pins(charter)?;
    crate::norm_reference_inventory::validate_classes(charter)?;
    let mut registry = VocabularyRegistry::default();
    let mut scopes: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    for scope in &charter.owner_scopes {
        let new_scope = scopes.insert(scope);
        if scope.trim().is_empty() || !new_scope {
            return Err(refused("C0 authority scopes must be nonempty and unique"));
        }
    }
    let mut gated = BTreeSet::new();
    for line in &charter.gated_refs {
        if line.trim().is_empty()
            || line == crate::branches::MAINLINE_BRANCH_ID
            || !gated.insert(line)
        {
            return Err(refused(
                "gated refs name distinct stream lines; the mainline is always gated",
            ));
        }
    }
    match &charter.activation {
        None => {}
        Some(AdmissionPredicate::Authority { scope }) if scopes.contains(scope) => {}
        Some(_) => {
            return Err(refused(
                "charter activation must require one of the charter's own authority scopes",
            ));
        }
    }
    let mut versions: std::collections::BTreeSet<VocabularyRef> = std::collections::BTreeSet::new();
    for entry in &charter.vocabularies {
        let vocabulary =
            Vocabulary::new(entry.definition.clone()).map_err(|e| refused(e.to_string()))?;
        let new_version = versions.insert(vocabulary.reference().clone());
        if !new_version {
            return Err(refused("C0 repeats a vocabulary version"));
        }
        crate::norm_inventory::validate_inventory_role(entry)?;
        crate::norm_relations::validate_relation_declaration(entry, charter)?;
        crate::norm_manifests::validate_manifest_declaration(entry)?;
        crate::norm_constraints::validate_constraint_declaration(entry)?;
        crate::norm_correspondence::validate_correspondence_declaration(entry)?;
        crate::norm_deployment::validate_deployment_declaration(entry)?;
        let mut effect_statuses = BTreeSet::new();
        for rule in entry.effectiveness.iter().flatten() {
            let unique = effect_statuses.insert(&rule.status);
            if !entry.definition.status.values.contains(&rule.status) || !unique {
                return Err(refused(
                    "effectiveness rules need unique statuses from their vocabulary",
                ));
            }
        }
        for predicate in std::iter::once(&entry.creation)
            .chain(entry.editing.iter())
            .chain(
                entry
                    .definition
                    .status
                    .transitions
                    .iter()
                    .map(|rule| &rule.admission),
            )
        {
            if let AdmissionPredicate::Authority { scope }
            | AdmissionPredicate::Witnessed { scope, .. }
            | AdmissionPredicate::Arbitrated { scope, .. } = predicate
            {
                if !scopes.contains(scope) {
                    return Err(refused(
                        "vocabulary references an undeclared C0 authority scope",
                    ));
                }
            }
        }
        // A witness is a premise of changing an existing record's status, and
        // it names relation families this charter declares.
        for predicate in std::iter::once(&entry.creation).chain(entry.editing.iter()) {
            if matches!(predicate, AdmissionPredicate::Witnessed { .. }) {
                return Err(refused("only a status transition may require a witness"));
            }
            if matches!(predicate, AdmissionPredicate::Arbitrated { .. }) {
                return Err(refused("only a status transition may be arbitrated"));
            }
        }
        for rule in &entry.definition.status.transitions {
            if let AdmissionPredicate::Arbitrated { arbitration, .. } = &rule.admission {
                let declared = |name: &str| {
                    entry
                        .definition
                        .fields
                        .iter()
                        .any(|field| field.name == name)
                };
                let named = [&arbitration.selectors, &arbitration.mode]
                    .into_iter()
                    .chain(&arbitration.expires);
                for field in named {
                    if !declared(field) {
                        return Err(refused(
                            "an arbitration names a field its vocabulary does not declare",
                        ));
                    }
                }
            }
        }
        let families: BTreeSet<&str> = charter
            .vocabularies
            .iter()
            .filter_map(|entry| entry.relation.as_ref())
            .map(|relation| relation.family.as_str())
            .collect();
        for rule in &entry.definition.status.transitions {
            if let AdmissionPredicate::Witnessed { witness, .. } = &rule.admission {
                if entry.relation.is_some() {
                    return Err(refused(
                        "a relation's own transitions cannot require a witness",
                    ));
                }
                let named = std::iter::once(&witness.family).chain(&witness.opposite_witnessed_by);
                for family in named {
                    if !families.contains(family.as_str()) {
                        return Err(refused(
                            "a witness names a relation family the charter does not declare",
                        ));
                    }
                }
            }
        }
        registry
            .register(vocabulary)
            .map_err(|e| refused(e.to_string()))?;
    }
    Ok(registry)
}

/// A record's state, and its effective revision, after one of its acts.
#[derive(Clone, Debug)]
struct RecordAct {
    event: String,
    charter_event: String,
    record: NormRecord,
    effective: Option<NormRecord>,
}

/// What an admission rule reads: records and their effective revisions, now
/// or as an act's causal past saw them.
struct Lens<'a> {
    records: Vec<&'a NormRecord>,
    effective: Vec<&'a NormRecord>,
}

/// A record's witnessed status as the current ledger derives it (D1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessedRecord {
    pub record: String,
    /// The status its history reached, which this view never revises.
    pub status: String,
    pub family: String,
    /// Whether the witness that admitted that status holds now.
    pub holds: bool,
    /// The effective records the witness relies on now.
    pub relied: Vec<String>,
    /// Why the witness does not hold, when it does not.
    pub reason: Option<String>,
}

impl NormView {
    fn bootstrap(event: &TrackerEvent, verifier: &dyn NormVerifier) -> StoreResult<Self> {
        let signed = verify_event(event, verifier)?;
        let NormAct::Bootstrap { creator, charter } = signed.statement.action else {
            return Err(refused("norm genesis must be a bootstrap act"));
        };
        let registry = registry_for(&charter)?;
        let reference_meaning_history = charter
            .vocabularies
            .iter()
            .map(|vocabulary| {
                (
                    (
                        vocabulary.definition.name.clone(),
                        vocabulary.definition.version.clone(),
                    ),
                    crate::norm_reference_inventory::classes_for(&charter, vocabulary),
                )
            })
            .collect();
        let mut nonces = BTreeMap::new();
        nonces.insert(
            (
                signed.statement.actor.principal.clone(),
                signed.statement.nonce,
            ),
            event.event_id.clone(),
        );
        Ok(Self {
            ledger: event.event_id.clone(),
            owner: signed.statement.actor,
            charter,
            records: BTreeMap::new(),
            effective_records: BTreeMap::new(),
            effective_lifecycles: BTreeMap::new(),
            revisions: BTreeMap::new(),
            family_heads: BTreeMap::new(),
            event_parents: BTreeMap::from([(event.event_id.clone(), Vec::new())]),
            record_acts: BTreeMap::new(),
            manifest_bases: BTreeMap::new(),
            authority_head: event.event_id.clone(),
            frontier: BTreeSet::from([event.event_id.clone()]),
            charter_events: vec![event.event_id.clone()],
            reference_meaning_history,
            authority_history: BTreeSet::from([event.event_id.clone()]),
            event_order: vec![event.event_id.clone()],
            creator,
            registry,
            historical: Vec::new(),
            retired: BTreeSet::new(),
            nonces,
        })
    }

    fn permitted(&self, predicate: &AdmissionPredicate, actor: &NormActor) -> StoreResult<()> {
        let permitted = match predicate {
            AdmissionPredicate::Public {} => true,
            AdmissionPredicate::Authority { scope }
            | AdmissionPredicate::Witnessed { scope, .. }
            | AdmissionPredicate::Arbitrated { scope, .. } => {
                actor == &self.owner && self.charter.owner_scopes.contains(scope)
            }
        };
        if !permitted {
            return Err(refused(
                "norm act lacks the charter's authenticated governance authority",
            ));
        }
        Ok(())
    }

    fn creation_fields(
        &self,
        actor: &NormActor,
        vocabulary: &VocabularyRef,
        fields_json: &str,
    ) -> StoreResult<(String, Value)> {
        let Some(policy) = self.charter.vocabularies.iter().find(|entry| {
            entry.definition.name == vocabulary.name
                && entry.definition.version == vocabulary.version
        }) else {
            // MUTATION-SUCCESS-EXPR: Ok(("recorded".into(), serde_json::json!({})))
            return Err(refused("pinned vocabulary has no C0 creation policy"));
        };
        let definition = self
            .registry
            .get(vocabulary)
            .map_err(|e| refused(e.to_string()))?;
        self.permitted(&policy.creation, actor)?;
        let status = definition.definition().status.initial.clone();
        let fields = definition
            .parse_record_json(fields_json, &status)
            .map_err(|e| refused(e.to_string()))?;
        Ok((status, fields))
    }

    /// Preview only: no signature or durable admission is established here.
    pub(crate) fn preview_creation(&self, statement: &NormStatement) -> StoreResult<()> {
        validate_statement_metadata(statement)?;
        let NormAct::Create {
            ledger,
            authority,
            vocabulary,
            fields_json,
        } = &statement.action
        else {
            return Err(refused("creation preview requires a create statement"));
        };
        self.check_ledger(ledger)?;
        self.check_authority(authority.as_deref().unwrap_or(ledger))?;
        if self
            .nonces
            .contains_key(&(statement.actor.principal.clone(), statement.nonce.clone()))
        {
            return Err(refused("norm invocation nonce was already admitted"));
        }
        let (status, fields) = self.creation_fields(&statement.actor, vocabulary, fields_json)?;
        self.check_relation_act(
            None,
            vocabulary,
            &fields,
            &status,
            statement.premises.as_ref(),
        )?;
        self.check_manifest_act(vocabulary, &fields, statement.premises.as_ref())?;
        self.check_correspondence_act(vocabulary, &fields, statement.premises.as_ref())?;
        Ok(())
    }

    fn apply(&mut self, event: &TrackerEvent, verifier: &dyn NormVerifier) -> StoreResult<()> {
        let signed = verify_event(event, verifier)?;
        let statement = signed.statement;
        let nonce = (statement.actor.principal.clone(), statement.nonce);
        if self.nonces.contains_key(&nonce) {
            return Err(refused(
                "norm invocation nonce was already admitted as a different event",
            ));
        }
        match statement.action {
            NormAct::Bootstrap { .. } => {
                // MUTATION-SUCCESS-EXPR: Ok(())
                return Err(refused("second bootstrap cannot replace norm identity"));
            }
            NormAct::Create {
                ledger,
                authority,
                vocabulary,
                fields_json,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(authority.as_deref().unwrap_or(&ledger))?;
                let (status, fields) =
                    self.creation_fields(&statement.actor, &vocabulary, &fields_json)?;
                self.check_relation_act(
                    None,
                    &vocabulary,
                    &fields,
                    &status,
                    statement.premises.as_ref(),
                )?;
                let manifest_basis =
                    self.check_manifest_act(&vocabulary, &fields, statement.premises.as_ref())?;
                self.check_correspondence_act(&vocabulary, &fields, statement.premises.as_ref())?;
                if let Some(basis) = manifest_basis {
                    self.manifest_bases.insert(event.event_id.clone(), basis);
                }
                self.records.insert(
                    event.event_id.clone(),
                    NormRecord {
                        id: event.event_id.clone(),
                        vocabulary,
                        fields,
                        content_head: event.event_id.clone(),
                        status,
                        head: event.event_id.clone(),
                    },
                );
                self.revisions.insert(
                    event.event_id.clone(),
                    self.records[&event.event_id].clone(),
                );
                self.advance_family(
                    &self.records[&event.event_id].vocabulary.clone(),
                    &event.event_id,
                );
            }
            NormAct::Transition {
                ledger,
                authority,
                vocabulary,
                record,
                previous,
                status,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(authority.as_deref().unwrap_or(&ledger))?;
                let current = self.current_record(&record, &vocabulary, &previous)?;
                let definition = self
                    .registry
                    .get(&current.vocabulary)
                    .map_err(|e| refused(e.to_string()))?;
                let predicate = definition
                    .transition(&current.status, &status)
                    .map_err(|e| refused(e.to_string()))?;
                self.permitted(predicate, &statement.actor)?;
                if let AdmissionPredicate::Witnessed { witness, .. } = predicate {
                    // A witnessed record is never a relation (the charter is
                    // validated so), so its premises bind the witness instead.
                    let lens = self.causal_lens(&event.parents);
                    self.witness_evidence(witness, current, &lens)?;
                } else if let AdmissionPredicate::Arbitrated { arbitration, .. } = predicate {
                    let lens = self.causal_lens(&event.parents);
                    self.check_arbitration(
                        arbitration,
                        current,
                        &status,
                        &statement.created_at,
                        &lens,
                    )?;
                } else {
                    self.check_relation_act(
                        Some(&record),
                        &vocabulary,
                        &current.fields,
                        &status,
                        statement.premises.as_ref(),
                    )?;
                }
                // A deployment binds the frontier its support was judged at
                // (norm-plane §10), so every replay applies it after that.
                if self
                    .deployed_cuts(&current.vocabulary, &record, &status)
                    .is_some()
                    && statement
                        .premises
                        .as_ref()
                        .is_none_or(|premises| premises.inventory_frontier.is_empty())
                {
                    return Err(refused(
                        "a deployment binds the ledger frontier its support was judged at",
                    ));
                }
                let mut updated = current.clone();
                updated.status = status;
                updated.head = event.event_id.clone();
                self.records.insert(record, updated);
                self.advance_family(&vocabulary, &event.event_id);
            }
            NormAct::Edit {
                ledger,
                authority,
                vocabulary,
                record,
                previous,
                fields_json,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(authority.as_deref().unwrap_or(&ledger))?;
                let current = self.current_record(&record, &vocabulary, &previous)?;
                let Some(policy) = self
                    .charter
                    .vocabularies
                    .iter()
                    .find(|entry| {
                        entry.definition.name == vocabulary.name
                            && entry.definition.version == vocabulary.version
                    })
                    .and_then(|entry| entry.editing.as_ref())
                else {
                    // MUTATION-SUCCESS-EXPR: Ok(())
                    return Err(refused("vocabulary has no edit rule"));
                };
                self.permitted(policy, &statement.actor)?;
                let definition = self
                    .registry
                    .get(&vocabulary)
                    .map_err(|e| refused(e.to_string()))?;
                let initial = &definition.definition().status.initial;
                let fields = definition
                    .parse_record_json(&fields_json, initial)
                    .map_err(|e| refused(e.to_string()))?;
                let content_changed = fields != current.fields;
                let resulting_status = if content_changed {
                    initial.clone()
                } else {
                    current.status.clone()
                };
                self.check_relation_act(
                    Some(&record),
                    &vocabulary,
                    &fields,
                    &resulting_status,
                    statement.premises.as_ref(),
                )?;
                let manifest_basis =
                    self.check_manifest_act(&vocabulary, &fields, statement.premises.as_ref())?;
                self.check_correspondence_act(&vocabulary, &fields, statement.premises.as_ref())?;
                let mut updated = current.clone();
                match manifest_basis {
                    Some(basis) => {
                        self.manifest_bases.insert(record.clone(), basis);
                    }
                    None => {
                        self.manifest_bases.remove(&record);
                    }
                }
                if content_changed {
                    updated.fields = fields;
                    updated.content_head = event.event_id.clone();
                    updated.status = resulting_status;
                }
                updated.head = event.event_id.clone();
                if content_changed {
                    self.revisions
                        .insert(event.event_id.clone(), updated.clone());
                }
                self.records.insert(record, updated);
                self.advance_family(&vocabulary, &event.event_id);
            }
            NormAct::Retire {
                ledger,
                authority,
                vocabulary,
                record,
                previous,
                revision,
                activation,
                status,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(authority.as_deref().unwrap_or(&ledger))?;
                let current = self.current_record(&record, &vocabulary, &previous)?;
                let Some(effective) = self.effective_records.get(&record) else {
                    // MUTATION-SUCCESS-EXPR: Ok(())
                    return Err(refused("retirement requires an active accepted revision"));
                };
                if effective.content_head != revision || effective.head != activation {
                    return Err(refused(
                        "retirement must name the exact active revision and activation",
                    ));
                }
                let retiring = self.effectiveness_rules(effective).is_some_and(|rules| {
                    rules
                        .iter()
                        .any(|rule| rule.status == status && rule.effect == RevisionEffect::Retire)
                });
                if !retiring {
                    return Err(refused(
                        "retirement target status has no declared retiring effect",
                    ));
                }
                let definition = self
                    .registry
                    .get(&vocabulary)
                    .map_err(|e| refused(e.to_string()))?;
                // Use the effective content's latest lifecycle, not a newer
                // draft's public rule or an earlier activation's stale rule.
                let predicate = definition
                    .transition(&self.effective_lifecycles[&record].status, &status)
                    .map_err(|e| refused(e.to_string()))?;
                self.permitted(predicate, &statement.actor)?;
                let mut updated = current.clone();
                if current.content_head == revision {
                    updated.status = status;
                }
                // Serialize with edits and reacceptance without changing draft content.
                updated.head = event.event_id.clone();
                self.records.insert(record.clone(), updated);
                self.effective_records.remove(&record);
                self.effective_lifecycles.remove(&record);
                self.advance_family(&vocabulary, &event.event_id);
            }
            NormAct::Rotate {
                ledger,
                previous,
                successor,
                frontier,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(&previous)?;
                if statement.actor != self.owner
                    || successor.principal != self.owner.principal
                    || successor == self.owner
                {
                    return Err(refused(
                        "root rotation requires its owner and a distinct bound successor key",
                    ));
                }
                let expected: Vec<_> = self.frontier.iter().cloned().collect();
                if frontier != expected {
                    return Err(refused(
                        "root rotation must close the exact current event frontier",
                    ));
                }
                self.owner = successor;
                self.authority_head = event.event_id.clone();
                self.authority_history.insert(event.event_id.clone());
            }
            NormAct::Activate {
                ledger,
                previous,
                charter,
                migration,
                changes,
                frontier,
            } => {
                self.check_ledger(&ledger)?;
                self.check_authority(&previous)?;
                let Some(rule) = self.charter.activation.clone() else {
                    // MUTATION-SUCCESS-EXPR: Ok(())
                    return Err(refused("the charter in force declares no activation rule"));
                };
                self.permitted(&rule, &statement.actor)?;
                let expected: Vec<_> = self.frontier.iter().cloned().collect();
                if frontier != expected {
                    return Err(refused(
                        "charter activation must close the exact current event frontier",
                    ));
                }
                let obstructions = self.activation_obstructions(&charter, &migration, &changes)?;
                if !obstructions.is_empty() {
                    return Err(crate::norm_activation::obstruction_refusal(&obstructions));
                }
                self.activate(&event.event_id, charter, &migration)?;
                self.authority_head = event.event_id.clone();
                self.authority_history.insert(event.event_id.clone());
            }
        }
        // Only an admitted lifecycle act (or an explicitly activating initial
        // state) changes effectiveness. Editing never reapplies an activation.
        if event.kind == CREATE_KIND || event.kind == TRANSITION_KIND {
            let record_id = event.issue_id.as_deref().unwrap_or(&event.event_id);
            self.project_effectiveness(record_id);
        }
        let touched = event.issue_id.as_deref().unwrap_or(&event.event_id);
        if let Some(record) = self.records.get(touched) {
            let act = RecordAct {
                event: event.event_id.clone(),
                charter_event: self
                    .charter_events
                    .last()
                    .expect("bootstrap charter")
                    .clone(),
                record: record.clone(),
                effective: self.effective_records.get(touched).cloned(),
            };
            self.record_acts
                .entry(touched.to_owned())
                .or_default()
                .push(act);
        }
        self.event_parents
            .insert(event.event_id.clone(), event.parents.clone());
        for parent in &event.parents {
            self.frontier.remove(parent);
        }
        self.frontier.insert(event.event_id.clone());
        self.event_order.push(event.event_id.clone());
        self.nonces.insert(nonce, event.event_id.clone());
        Ok(())
    }

    fn effectiveness_rules(&self, record: &NormRecord) -> Option<&[EffectivenessRule]> {
        self.interpretation(&record.vocabulary)
            .and_then(|v| v.effectiveness.as_deref())
    }

    /// The declaration that interprets a vocabulary's records: the charter in
    /// force's, or an earlier charter's for a vocabulary no longer in force.
    pub fn interpretation(&self, vocabulary: &VocabularyRef) -> Option<&NormVocabulary> {
        self.charter
            .vocabularies
            .iter()
            .chain(&self.historical)
            .find(|entry| crate::norm_activation::same_version(entry, vocabulary))
    }

    /// Every declaration that interprets a record of this ledger, in force first.
    pub fn interpreted_vocabularies(&self) -> impl Iterator<Item = &NormVocabulary> {
        self.charter.vocabularies.iter().chain(&self.historical)
    }

    /// Every record act observed by this replay. A later charter activation
    /// contributes a new interpretation even when content_head stays fixed.
    pub(crate) fn observed_reference_admissions(
        &self,
    ) -> Vec<crate::norm_reference_inventory::NormReferenceAdmission> {
        let mut admissions = self
            .record_acts
            .iter()
            .flat_map(|(record_id, acts)| {
                acts.iter().map(
                    |act| crate::norm_reference_inventory::NormReferenceAdmission {
                        event: act.event.clone(),
                        record: record_id.clone(),
                        content_head: act.record.content_head.clone(),
                        charter_event: act.charter_event.clone(),
                        vocabulary: act.record.vocabulary.clone(),
                        status: act.record.status.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        admissions
            .sort_by(|left, right| (&left.event, &left.record).cmp(&(&right.event, &right.record)));
        admissions
    }

    /// Retain each act's own content and interpretation for read-only
    /// reference extraction. Looking up `records` here would replace older
    /// accepted content with the record's current revision.
    pub(crate) fn observed_reference_snapshots(&self) -> Vec<(String, String, NormRecord)> {
        let mut snapshots = self
            .record_acts
            .values()
            .flat_map(|acts| {
                acts.iter().map(|act| {
                    (
                        act.event.clone(),
                        act.charter_event.clone(),
                        act.record.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| (&left.0, &left.2.id).cmp(&(&right.0, &right.2.id)));
        snapshots
    }

    /// Move the ledger onto an admitted activation's charter: live records
    /// migrate or retire as planned, and every declaration the new charter
    /// drops stays behind to interpret what its records were.
    fn activate(
        &mut self,
        event_id: &str,
        charter: NormCharter,
        migration: &[crate::norm_activation::VocabularyMigration],
    ) -> StoreResult<()> {
        use crate::norm_activation::MigrationPlan;
        for entry in &charter.vocabularies {
            let vocabulary =
                Vocabulary::new(entry.definition.clone()).map_err(|e| refused(e.to_string()))?;
            self.registry
                .register(vocabulary)
                .map_err(|e| refused(e.to_string()))?;
        }
        let preceding_charter = self
            .charter_events
            .last()
            .expect("bootstrap charter")
            .clone();
        let mut touched = Vec::new();
        for step in migration {
            let live: Vec<String> = self
                .records
                .values()
                .filter(|record| record.vocabulary == step.from && self.record_is_live(record))
                .map(|record| record.id.clone())
                .collect();
            for id in live {
                let interpretation_charter = match &step.plan {
                    MigrationPlan::Retain {} => continue,
                    MigrationPlan::Retire {} => {
                        self.retired.insert(id.clone());
                        self.effective_records.remove(&id);
                        self.effective_lifecycles.remove(&id);
                        preceding_charter.clone()
                    }
                    MigrationPlan::Successor {
                        vocabulary,
                        statuses,
                    } => {
                        if let Some(effective) = self.effective_records.get_mut(&id) {
                            effective.vocabulary = vocabulary.clone();
                            effective.status = statuses[&effective.status].clone();
                        }
                        if let Some(lifecycle) = self.effective_lifecycles.get_mut(&id) {
                            lifecycle.status = statuses[&lifecycle.status].clone();
                        }
                        let record = self.records.get_mut(&id).expect("live record exists");
                        record.vocabulary = vocabulary.clone();
                        record.status = statuses[&record.status].clone();
                        event_id.to_owned()
                    }
                };
                let record = self.records.get_mut(&id).expect("live record exists");
                record.head = event_id.to_owned();
                touched.push((id, interpretation_charter));
            }
        }
        let dropped: Vec<NormVocabulary> = self
            .charter
            .vocabularies
            .iter()
            .filter(|entry| !charter.vocabularies.contains(entry))
            .cloned()
            .collect();
        for entry in dropped {
            if !self.historical.contains(&entry) {
                self.historical.push(entry);
            }
        }
        self.historical
            .retain(|entry| !charter.vocabularies.contains(entry));
        for entry in &charter.vocabularies {
            self.reference_meaning_history.insert(
                (
                    entry.definition.name.clone(),
                    entry.definition.version.clone(),
                ),
                crate::norm_reference_inventory::classes_for(&charter, entry),
            );
        }
        self.charter = charter;
        self.charter_events.push(event_id.to_owned());
        for (id, charter_event) in touched {
            let vocabulary = self.records[&id].vocabulary.clone();
            self.advance_family(&vocabulary, event_id);
            let act = RecordAct {
                event: event_id.to_owned(),
                charter_event,
                record: self.records[&id].clone(),
                effective: self.effective_records.get(&id).cloned(),
            };
            self.record_acts.entry(id).or_default().push(act);
        }
        Ok(())
    }

    /// Read-only projection under the record's pinned charter. Consumers must
    /// retain Unspecified as an inventory gap rather than treating it as Inactive.
    pub fn effective_revision(&self, record: &NormRecord) -> EffectiveRevision {
        if self.effectiveness_rules(record).is_none() {
            return EffectiveRevision::Unspecified;
        }
        match self.effective_records.get(&record.id) {
            Some(effective) => EffectiveRevision::Active {
                record: Box::new(effective.clone()),
                lifecycle: self.effective_lifecycles[&record.id].clone(),
            },
            None => EffectiveRevision::Inactive,
        }
    }

    fn project_effectiveness(&mut self, record_id: &str) {
        let current = &self.records[record_id];
        let effect = self.effectiveness_rules(current).and_then(|rules| {
            rules
                .iter()
                .find(|r| r.status == current.status)
                .map(|r| r.effect)
        });
        match effect {
            Some(RevisionEffect::Activate) => {
                self.effective_records
                    .insert(record_id.into(), current.clone());
            }
            Some(RevisionEffect::Retire) => {
                let same_revision = self
                    .effective_records
                    .get(record_id)
                    .is_some_and(|effective| effective.content_head == current.content_head);
                if same_revision {
                    self.effective_records.remove(record_id);
                    self.effective_lifecycles.remove(record_id);
                }
            }
            None => {}
        }
        if self
            .effective_records
            .get(record_id)
            .is_some_and(|effective| effective.content_head == current.content_head)
        {
            self.effective_lifecycles.insert(
                record_id.into(),
                EffectiveLifecycle {
                    status: current.status.clone(),
                    head: current.head.clone(),
                },
            );
        }
    }

    /// The ledger as it stands now.
    fn current_lens(&self) -> Lens<'_> {
        Lens {
            records: self
                .records
                .values()
                .filter(|record| !self.retired.contains(&record.id))
                .collect(),
            effective: self.effective_records.values().collect(),
        }
    }

    /// The ledger as an act's causal past saw it: each record after its latest
    /// act among the act's ancestors. An admission rule judged through it gives
    /// the same verdict whichever order a replay applies concurrent acts in.
    fn causal_lens(&self, parents: &[String]) -> Lens<'_> {
        let mut past = BTreeSet::new();
        let mut pending: Vec<&str> = parents.iter().map(String::as_str).collect();
        while let Some(event) = pending.pop() {
            if past.insert(event.to_owned()) {
                if let Some(grandparents) = self.event_parents.get(event) {
                    pending.extend(grandparents.iter().map(String::as_str));
                }
            }
        }
        let mut lens = Lens {
            records: Vec::new(),
            effective: Vec::new(),
        };
        // A retired record counts for no later act: the activation that
        // retired it closed the frontier, so every later act descends from it.
        for (id, acts) in &self.record_acts {
            if self.retired.contains(id) {
                continue;
            }
            if let Some(act) = acts.iter().rev().find(|act| past.contains(&act.event)) {
                lens.records.push(&act.record);
                lens.effective.extend(act.effective.as_ref());
            }
        }
        lens
    }

    /// The premises a new act must bind, checked when it is appended against
    /// everything the ledger then holds (norm-plane §5, §6). A replay never
    /// re-runs these: the act's causal past is what it then judges against.
    pub(crate) fn check_admission_premises(
        &self,
        event: &TrackerEvent,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<()> {
        let statement = verify_event(event, verifier)?.statement;
        let NormAct::Transition {
            vocabulary,
            record,
            previous,
            status,
            ..
        } = statement.action
        else {
            return Ok(());
        };
        let Ok(current) = self.current_record(&record, &vocabulary, &previous) else {
            return Ok(());
        };
        let Ok(definition) = self.registry.get(&current.vocabulary) else {
            return Ok(());
        };
        let Ok(predicate) = definition.transition(&current.status, &status) else {
            return Ok(());
        };
        // An act the replay refuses anyway (here, for authority) is refused
        // there with its own reason, not for what it failed to bind.
        if self.permitted(predicate, &statement.actor).is_err() {
            return Ok(());
        }
        if let AdmissionPredicate::Witnessed { witness, .. } = predicate {
            self.check_witness_binding(witness, current, statement.premises.as_ref())?;
        }
        if let AdmissionPredicate::Arbitrated { arbitration, .. } = predicate {
            // The arbiter judges everything the ledger holds now — a grant the
            // grant has not bound is still a grant — and then asks the grant
            // to bind what it judged, so its replay judges the same claims.
            let lens = self.current_lens();
            self.check_arbitration(arbitration, current, &status, &statement.created_at, &lens)?;
            self.check_arbitration_binding(arbitration, current, statement.premises.as_ref())?;
        }

        Ok(())
    }

    /// The exclusive claims of a record's vocabulary, other than the record,
    /// whose regions overlap its region, future members included.
    fn overlapping_claims<'a>(
        arbitration: &Arbitration,
        record: &NormRecord,
        records: &[&'a NormRecord],
    ) -> Vec<&'a NormRecord> {
        let selectors = |claim: &NormRecord| -> Vec<String> {
            claim.fields[&arbitration.selectors]
                .as_array()
                .map(|selectors| {
                    selectors
                        .iter()
                        .filter_map(|selector| selector.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mine = selectors(record);
        records
            .iter()
            .copied()
            .filter(|other| {
                other.id != record.id
                    && other.vocabulary == record.vocabulary
                    && other.fields[&arbitration.mode] == arbitration.exclusive
                    && crate::norm_reservations::claims_overlap(&mine, &selectors(other))
            })
            .collect()
    }

    /// The arbiter's grant (norm-plane §7, R1): an exclusive claim is granted
    /// only when no other exclusive claim of its vocabulary, already in the
    /// target status and unexpired at the granting act's time, overlaps it,
    /// future members included. It is judged against the grant's causal past,
    /// so a replay gives the verdict the arbiter gave.
    fn check_arbitration(
        &self,
        arbitration: &Arbitration,
        record: &NormRecord,
        status: &str,
        at: &str,
        lens: &Lens<'_>,
    ) -> StoreResult<()> {
        if record.fields[&arbitration.mode] != arbitration.exclusive {
            return Ok(());
        }
        let unexpired = |claim: &NormRecord| {
            arbitration
                .expires
                .as_ref()
                .and_then(|field| claim.fields[field].as_str())
                .is_none_or(|expires| !crate::norm_reservations::lapsed(expires, at))
        };
        if let Some(held) = Self::overlapping_claims(arbitration, record, &lens.records)
            .into_iter()
            .find(|other| other.status == status && unexpired(other))
        {
            return Err(refused(format!(
                "an exclusive grant would overlap {}, which is {status} and unexpired",
                held.id
            )));
        }
        Ok(())
    }

    /// What an arbitrated grant must bind when it is appended: the current head
    /// of every overlapping exclusive claim that has left its initial status,
    /// so everything the arbiter judged is in the grant's causal past.
    fn check_arbitration_binding(
        &self,
        arbitration: &Arbitration,
        record: &NormRecord,
        premises: Option<&NormPremises>,
    ) -> StoreResult<()> {
        let Ok(definition) = self.registry.get(&record.vocabulary) else {
            return Ok(());
        };
        let initial = &definition.definition().status.initial;
        let references = premises
            .map(|premises| premises.references.as_slice())
            .unwrap_or(&[]);
        let records: Vec<&NormRecord> = self
            .records
            .values()
            .filter(|record| !self.retired.contains(&record.id))
            .collect();
        if let Some(unbound) = Self::overlapping_claims(arbitration, record, &records)
            .into_iter()
            .find(|other| &other.status != initial && !references.contains(&other.head))
        {
            return Err(refused(format!(
                "an arbitrated grant must bind the current head of every overlapping claim it judged; {} is not bound",
                unbound.id
            )));
        }
        Ok(())
    }

    /// The snapshot's reservations: the conflicts among live claims.
    pub fn reservations_view(&self) -> crate::norm_reservations::ReservationsView {
        crate::norm_reservations::ReservationsView {
            conflicts: self.reservation_conflicts(),
        }
    }

    /// Every pair of live claims whose regions overlap, at least one of them
    /// exclusive, in each vocabulary whose grant is arbitrated (norm-plane §7):
    /// a merge keeps both, and the conflict names both holders. A claim is live
    /// in its vocabulary's initial status and in an arbitrated status.
    pub fn reservation_conflicts(&self) -> Vec<crate::norm_reservations::ReservationConflict> {
        let holder = |id: &str| {
            self.nonces
                .iter()
                .find(|(_, event)| event.as_str() == id)
                .map(|((principal, _), _)| principal.clone())
                .unwrap_or_default()
        };
        let mut conflicts = Vec::new();
        for entry in &self.charter.vocabularies {
            let Some((arbitration, granted)) =
                entry
                    .definition
                    .status
                    .transitions
                    .iter()
                    .find_map(|rule| match &rule.admission {
                        AdmissionPredicate::Arbitrated { arbitration, .. } => {
                            Some((arbitration, rule.to.clone()))
                        }
                        _ => None,
                    })
            else {
                continue;
            };
            let initial = &entry.definition.status.initial;
            let claims: Vec<(&NormRecord, Vec<String>, bool)> = self
                .records
                .values()
                .filter(|record| {
                    record.vocabulary.name == entry.definition.name
                        && record.vocabulary.version == entry.definition.version
                        && !self.retired.contains(&record.id)
                        && (&record.status == initial || record.status == granted)
                })
                .map(|record| {
                    let selectors = record.fields[&arbitration.selectors]
                        .as_array()
                        .map(|selectors| {
                            selectors
                                .iter()
                                .filter_map(|selector| selector.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let exclusive = record.fields[&arbitration.mode] == arbitration.exclusive;
                    (record, selectors, exclusive)
                })
                .collect();
            for (index, (a, a_selectors, a_exclusive)) in claims.iter().enumerate() {
                for (b, b_selectors, b_exclusive) in &claims[index + 1..] {
                    if (*a_exclusive || *b_exclusive)
                        && crate::norm_reservations::claims_overlap(a_selectors, b_selectors)
                    {
                        conflicts.push(crate::norm_reservations::ReservationConflict {
                            claims: [a.id.clone(), b.id.clone()],
                            holders: [holder(&a.id), holder(&b.id)],
                            statuses: [a.status.clone(), b.status.clone()],
                            selectors: [a_selectors.clone(), b_selectors.clone()],
                        });
                    }
                }
            }
        }
        conflicts
    }

    /// A witnessed transition's premise (norm-plane §6, D1): a live relation of
    /// the witness's family binds the record's current revision, on the
    /// declared side, to an effective revision on the other; and when the
    /// witness names a second family, a live edge of it targets each of those.
    ///
    /// The transition binds what it relied on as premises, so a replay orders
    /// it after them: the witness family's basis, which a moved family refuses
    /// for re-evaluation; the act that made each relied-on revision effective;
    /// and the second family's basis when the witness names one.
    fn check_witness_binding(
        &self,
        witness: &Witness,
        record: &NormRecord,
        premises: Option<&NormPremises>,
    ) -> StoreResult<()> {
        let basis = self.relation_family(&witness.family)?.basis;
        match premises.and_then(|premises| premises.family_basis.as_deref()) {
            Some(bound) if bound == basis => {}
            Some(_) => {
                return Err(refused(
                    "the witness family's basis moved since it was captured; re-evaluate the transition",
                ))
            }
            None => {
                return Err(refused(
                    "a witnessed transition must bind its witness family's basis as a premise",
                ))
            }
        }
        let references = premises
            .map(|premises| premises.references.as_slice())
            .unwrap_or(&[]);
        let (_, heads) = self.witness_evidence(witness, record, &self.current_lens())?;
        if heads.iter().any(|head| !references.contains(head)) {
            return Err(refused(
                "a witnessed transition must bind the act that made each revision it relies on effective",
            ));
        }
        if let Some(second) = &witness.opposite_witnessed_by {
            if !references.contains(&self.relation_family(second)?.basis) {
                return Err(refused(format!(
                    "a witnessed transition must bind the {second} family's basis as a premise"
                )));
            }
        }
        Ok(())
    }

    /// Evaluate a witness against this view: the effective revisions it
    /// relies on, and the acts that made them effective. A witness that does
    /// not hold is refused with the reason.
    fn witness_evidence(
        &self,
        witness: &Witness,
        record: &NormRecord,
        lens: &Lens<'_>,
    ) -> StoreResult<(BTreeSet<String>, Vec<String>)> {
        let names = |id: &str, record: &NormRecord| id == record.content_head || id == record.id;
        // The act that made a revision effective, when it is effective.
        let effective = |id: &str| {
            lens.effective
                .iter()
                .find(|record| names(id, record))
                .map(|record| record.head.clone())
        };
        let edges = self.live_relation_endpoints(&witness.family, &lens.records);
        let opposite: BTreeSet<String> = edges
            .iter()
            .filter_map(|(source, target)| match witness.side {
                WitnessSide::Source if names(source, record) => Some(target.clone()),
                WitnessSide::Target if names(target, record) => Some(source.clone()),
                _ => None,
            })
            .filter(|opposite| effective(opposite).is_some())
            .collect();
        if opposite.is_empty() {
            return Err(refused(format!(
                "the transition's witness does not hold: no live {} relation binds this revision to an effective one",
                witness.family
            )));
        }
        if let Some(second) = &witness.opposite_witnessed_by {
            let witnessed: BTreeSet<String> = self
                .live_relation_endpoints(second, &lens.records)
                .into_iter()
                .map(|(_, target)| target)
                .collect();
            if let Some(unwitnessed) = opposite.iter().find(|id| !witnessed.contains(*id)) {
                return Err(refused(format!(
                    "the transition's witness does not hold: {unwitnessed} has no live {second} relation"
                )));
            }
        }
        let heads = opposite.iter().filter_map(|id| effective(id)).collect();
        Ok((opposite, heads))
    }

    /// The derived current state of every record whose status its charter
    /// reaches only through a witness (norm-plane §6, D1): whether that witness
    /// still holds now, and what it relies on. The lifecycle is history and is
    /// never revised by this view.
    pub fn witnessed_records(&self) -> Vec<WitnessedRecord> {
        let mut witnessed = Vec::new();
        for record in self.records.values() {
            let Ok(definition) = self.registry.get(&record.vocabulary) else {
                continue;
            };
            let Some(witness) = definition
                .definition()
                .status
                .transitions
                .iter()
                .filter(|rule| rule.to == record.status)
                .find_map(|rule| match &rule.admission {
                    AdmissionPredicate::Witnessed { witness, .. } => Some(witness),
                    _ => None,
                })
            else {
                continue;
            };
            let (holds, relied, reason) =
                match self.witness_evidence(witness, record, &self.current_lens()) {
                    Ok((opposite, _)) => (
                        true,
                        opposite
                            .iter()
                            .filter_map(|id| {
                                self.effective_records
                                    .values()
                                    .find(|effective| {
                                        effective.content_head == *id || effective.id == *id
                                    })
                                    .map(|effective| effective.id.clone())
                            })
                            .collect(),
                        None,
                    ),
                    Err(StoreError::Conflict(reason)) => (false, Vec::new(), Some(reason)),
                    Err(other) => (false, Vec::new(), Some(format!("{other:?}"))),
                };
            witnessed.push(WitnessedRecord {
                record: record.id.clone(),
                status: record.status.clone(),
                family: witness.family.clone(),
                holds,
                relied,
                reason,
            });
        }
        witnessed
    }

    /// The endpoint values of every live relation record in a family, as the
    /// relation's reference fields name them.
    fn live_relation_endpoints(
        &self,
        family: &str,
        records: &[&NormRecord],
    ) -> Vec<(String, String)> {
        records
            .iter()
            .filter_map(|record| {
                let (_, relation) = self.relation_of(&record.vocabulary)?;
                if relation.family != family
                    || !relation.live_statuses.contains(&record.status)
                    || self.retired.contains(&record.id)
                {
                    return None;
                }
                Some((
                    record.fields[&relation.source].as_str()?.to_owned(),
                    record.fields[&relation.target].as_str()?.to_owned(),
                ))
            })
            .collect()
    }

    pub(crate) fn relation_of(
        &self,
        vocabulary: &VocabularyRef,
    ) -> Option<(&NormVocabulary, &RelationDeclaration)> {
        self.interpretation(vocabulary)
            .and_then(|entry| entry.relation.as_ref().map(|relation| (entry, relation)))
    }

    /// Resolve one declared reference field to the record it names, by the
    /// form the declaration gives it, and check the record's kind.
    fn resolve_endpoint(
        &self,
        entry: &NormVocabulary,
        fields: &Value,
        field: &str,
        kinds: &[String],
    ) -> StoreResult<String> {
        // The declaration was validated with the charter and the interpreter
        // validated the fields, so an absent form or value cannot happen; both
        // fall into the one refusal a caller can reach, an unresolved endpoint.
        let form = entry
            .definition
            .fields
            .iter()
            .find(|declared| declared.name == field)
            .and_then(|declared| match declared.value_type {
                ValueType::Reference { form } => Some(form),
                _ => None,
            });
        let reference = fields.get(field).and_then(Value::as_str);
        let record_id = match (form, reference) {
            (Some(ReferenceForm::Identity), Some(reference)) => self
                .records
                .contains_key(reference)
                .then(|| reference.to_owned()),
            (Some(ReferenceForm::Revision), Some(reference)) => self
                .revisions
                .get(reference)
                .map(|record| record.id.clone()),
            _ => None,
        };
        let Some(record_id) = record_id else {
            // The negative control resolves a dangling reference to the reference itself.
            // MUTATION-SUCCESS-EXPR: Ok(reference.to_owned())
            return Err(refused(
                "relation endpoint does not resolve at this frontier",
            ));
        };
        if !kinds.is_empty() && !kinds.contains(&self.records[&record_id].vocabulary.name) {
            return Err(refused(
                "relation endpoint is a record of an undeclared kind",
            ));
        }
        Ok(record_id)
    }

    /// Every family the charter declares, with its live edges at this frontier
    /// and the basis an act binds.
    pub fn relation_families(&self) -> StoreResult<BTreeMap<String, RelationFamilyView>> {
        let mut families: BTreeMap<String, Vec<RelationEdge>> = self
            .charter
            .vocabularies
            .iter()
            .filter_map(|entry| entry.relation.as_ref())
            .map(|relation| (relation.family.clone(), Vec::new()))
            .collect();
        for record in self.records.values() {
            let Some((entry, relation)) = self.relation_of(&record.vocabulary) else {
                continue;
            };
            if !relation.live_statuses.contains(&record.status) || self.retired.contains(&record.id)
            {
                continue;
            }
            let source = self.resolve_endpoint(
                entry,
                &record.fields,
                &relation.source,
                &relation.source_kinds,
            )?;
            let target = self.resolve_endpoint(
                entry,
                &record.fields,
                &relation.target,
                &relation.target_kinds,
            )?;
            families
                .entry(relation.family.clone())
                .or_default()
                .push(RelationEdge {
                    record: record.id.clone(),
                    revision: record.content_head.clone(),
                    relation: record.vocabulary.name.clone(),
                    source,
                    target,
                });
        }
        Ok(families
            .into_iter()
            .map(|(family, edges)| {
                let basis = self.family_basis(&family);
                (family, RelationFamilyView::new(basis, edges))
            })
            .collect())
    }

    fn family_basis(&self, family: &str) -> String {
        self.family_heads
            .get(family)
            .cloned()
            .unwrap_or_else(|| self.ledger.clone())
    }

    /// An admitted act on a relation record moves its family's basis.
    fn advance_family(&mut self, vocabulary: &VocabularyRef, event_id: &str) {
        if let Some((_, relation)) = self.relation_of(vocabulary) {
            let family = relation.family.clone();
            self.family_heads.insert(family, event_id.to_owned());
        }
    }

    pub fn relation_family(&self, family: &str) -> StoreResult<RelationFamilyView> {
        self.relation_families()?
            .remove(family)
            .ok_or_else(|| refused("charter declares no such relation family"))
    }

    /// The structural door for an act whose record is a relation. Every such
    /// act binds the family basis it was validated against, so the family's
    /// history is one causal chain; a moved basis is refused for re-evaluation,
    /// not substituted. Only an act that leaves the edge live is checked
    /// structurally. A non-relation act binds no basis.
    fn check_relation_act(
        &self,
        record: Option<&str>,
        vocabulary: &VocabularyRef,
        fields: &Value,
        status: &str,
        premises: Option<&NormPremises>,
    ) -> StoreResult<()> {
        let bound = premises.and_then(|premises| premises.family_basis.as_deref());
        let Some((entry, relation)) = self.relation_of(vocabulary) else {
            if bound.is_some() {
                return Err(refused("only an act on a relation binds a family basis"));
            }
            return Ok(());
        };
        let live = relation.live_statuses.iter().any(|value| value == status);
        let family = self.relation_family(&relation.family)?;
        match bound {
            Some(basis) if *basis == family.basis => {}
            Some(_) => {
                // The negative control substitutes the current basis for the stale one.
                // MUTATION-SUCCESS-EXPR: ()
                return Err(refused(
                    "family basis moved since it was captured; re-evaluate the relation against the current family",
                ));
            }
            None => {
                // Every act on a relation moves the family, so every one binds
                // the basis: the family's history is then one causal chain that
                // a replay walks in admission order, whatever the transport order.
                return Err(refused(
                    "an act on a relation must bind the family basis it was validated against",
                ));
            }
        }
        if !live {
            return Ok(());
        }
        let references = premises
            .map(|premises| premises.references.as_slice())
            .unwrap_or(&[]);
        for field in [&relation.source, &relation.target] {
            let named = fields.get(field).and_then(Value::as_str);
            if !named.is_some_and(|value| references.iter().any(|bound| bound == value)) {
                // The negative control lets an unbound reference through, so a
                // replay may apply the act before the record it names.
                // MUTATION-SUCCESS-EXPR: ()
                return Err(refused(
                    "an act that makes a relation live must bind the references it names as premises",
                ));
            }
        }
        let source =
            self.resolve_endpoint(entry, fields, &relation.source, &relation.source_kinds)?;
        let target =
            self.resolve_endpoint(entry, fields, &relation.target, &relation.target_kinds)?;
        if relation.acyclic {
            if source == target {
                return Err(refused(
                    "an acyclic relation cannot relate a record to itself",
                ));
            }
            if family.reaches(&target, &source, record) {
                // The negative control checks only the immediate reverse edge.
                // MUTATION-SUCCESS-EXPR: false
                return Err(refused(format!(
                    "relation would close a cycle in family {}",
                    relation.family
                )));
            }
        }
        if let Some(RelationCardinality::AtMostOneLivePerTarget) = relation.cardinality {
            let taken = family
                .edges
                .iter()
                .any(|edge| Some(edge.record.as_str()) != record && edge.target == target);
            if taken {
                return Err(refused(format!(
                    "family {} admits at most one live relation per target",
                    relation.family
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn manifest_of(
        &self,
        vocabulary: &VocabularyRef,
    ) -> Option<(&NormVocabulary, &ManifestDeclaration)> {
        self.interpretation(vocabulary)
            .and_then(|entry| entry.manifest.as_ref().map(|manifest| (entry, manifest)))
    }

    /// The record as it stood when this content revision was admitted: its
    /// fields, and its status and head at that act. Later lifecycle acts on
    /// the record do not move it.
    pub fn revision(&self, revision: &str) -> Option<&NormRecord> {
        self.revisions.get(revision)
    }

    /// Every content revision of one record admitted at this frontier, in
    /// admission order.
    pub fn revisions_of(&self, record: &str) -> Vec<String> {
        self.event_order
            .iter()
            .filter(|event| {
                self.revisions
                    .get(*event)
                    .is_some_and(|revision| revision.id == record)
            })
            .cloned()
            .collect()
    }

    /// The inventory frontier an admitted exhaustive manifest bound, if any.
    pub fn manifest_basis(&self, record: &str) -> Option<&[String]> {
        self.manifest_bases.get(record).map(Vec::as_slice)
    }

    /// The structural door for an act whose record is a manifest. Every
    /// member is bound as a premise and resolves to an admitted revision; an
    /// exhaustive claim binds the inventory frontier it was judged against,
    /// and a bounded claim binds none. Completeness is not decided here.
    fn check_manifest_act(
        &self,
        vocabulary: &VocabularyRef,
        fields: &Value,
        premises: Option<&NormPremises>,
    ) -> StoreResult<Option<Vec<String>>> {
        let frontier = premises
            .map(|premises| premises.inventory_frontier.as_slice())
            .unwrap_or(&[]);
        let Some((_, manifest)) = self.manifest_of(vocabulary) else {
            if !frontier.is_empty() {
                return Err(refused(
                    "only an act on a manifest binds an inventory frontier",
                ));
            }
            return Ok(None);
        };
        let references = premises
            .map(|premises| premises.references.as_slice())
            .unwrap_or(&[]);
        // The interpreter validated the members as a list of references, so
        // a missing list or a non-string member cannot reach this door.
        let members = fields
            .get(&manifest.members)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        for member in members {
            if !references.iter().any(|bound| bound == member) {
                // MUTATION-SUCCESS-EXPR: ()
                return Err(refused(
                    "an act on a manifest must bind the members it names as premises",
                ));
            }
            if !self.revisions.contains_key(member) {
                return Err(refused(
                    "manifest member does not resolve to an admitted revision",
                ));
            }
        }
        let claim = fields
            .get(&manifest.claim)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if claim != manifest.exhaustive {
            if !frontier.is_empty() {
                return Err(refused(
                    "a bounded manifest claim binds no inventory frontier",
                ));
            }
            return Ok(None);
        }
        if frontier.is_empty() {
            // The negative control takes the claim as its own basis.
            // MUTATION-SUCCESS-EXPR: Ok(Some(Vec::new()))
            return Err(refused(
                "an exhaustive manifest claim must bind the inventory frontier it was judged against",
            ));
        }
        let unique: BTreeSet<&String> = frontier.iter().collect();
        if unique.len() != frontier.len()
            || frontier.iter().any(|id| !self.event_order.contains(id))
        {
            return Err(refused(
                "a bound inventory frontier names each admitted event once",
            ));
        }
        Ok(Some(frontier.to_vec()))
    }

    /// The structural door for an act whose record is a correspondence. Both
    /// sides are nonempty, disjoint, bound as premises and resolve to admitted
    /// revisions. Nothing here touches the revisions it relates.
    fn check_correspondence_act(
        &self,
        vocabulary: &VocabularyRef,
        fields: &Value,
        premises: Option<&NormPremises>,
    ) -> StoreResult<()> {
        let Some(entry) = self.charter.vocabularies.iter().find(|entry| {
            entry.definition.name == vocabulary.name
                && entry.definition.version == vocabulary.version
        }) else {
            return Ok(());
        };
        let Some(correspondence) = entry.correspondence.as_ref() else {
            return Ok(());
        };
        let references = premises
            .map(|premises| premises.references.as_slice())
            .unwrap_or(&[]);
        let side = |field: &str| -> StoreResult<Vec<String>> {
            // The interpreter validated each side as a list of references.
            let values: Vec<&str> = fields
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if values.is_empty() {
                return Err(refused(
                    "a correspondence relates at least one revision on each side",
                ));
            }
            let mut side = Vec::with_capacity(values.len());
            for revision in values {
                if !references.iter().any(|bound| bound == revision) {
                    // MUTATION-SUCCESS-EXPR: ()
                    return Err(refused(
                        "an act on a correspondence must bind the revisions it names as premises",
                    ));
                }
                if !self.revisions.contains_key(revision) {
                    return Err(refused(
                        "correspondence member does not resolve to an admitted revision",
                    ));
                }
                side.push(revision.to_owned());
            }
            Ok(side)
        };
        let sources = side(&correspondence.sources)?;
        let targets = side(&correspondence.targets)?;
        if sources.iter().any(|source| targets.contains(source)) {
            return Err(refused(
                "a correspondence relates a revision to other revisions, not to itself",
            ));
        }
        Ok(())
    }

    fn current_record(
        &self,
        record: &str,
        vocabulary: &VocabularyRef,
        previous: &str,
    ) -> StoreResult<&NormRecord> {
        let Some(current) = self.records.get(record) else {
            // The negative control substitutes a different existing record.
            // MUTATION-SUCCESS-EXPR: Ok(self.records.values().next().expect("mutation fixture contains a record"))
            return Err(refused("norm record creation is missing"));
        };
        if current.vocabulary != *vocabulary || current.head != previous {
            return Err(refused(
                "norm act must name the exact record version and current head",
            ));
        }
        if self.retired.contains(record) {
            return Err(refused(
                "the record was retired by a charter activation; no act is admitted on it",
            ));
        }
        let in_force = self
            .charter
            .vocabularies
            .iter()
            .any(|entry| crate::norm_activation::same_version(entry, vocabulary));
        if !in_force {
            return Err(refused(
                "the record's vocabulary is no longer in force; its history is read-only",
            ));
        }
        Ok(current)
    }

    pub fn checkpoint(&self) -> NormCheckpoint {
        NormCheckpoint {
            ledger: self.ledger.clone(),
            authority_head: self.authority_head.clone(),
        }
    }

    /// Admission has already verified the union; hosts use this order when
    /// inserting imported events so authority-checkpoint triggers advance in
    /// causal order even when transport arrives reversed.
    pub fn event_order(&self) -> &[String] {
        &self.event_order
    }

    fn check_authority(&self, authority: &str) -> StoreResult<()> {
        if authority != self.authority_head {
            return Err(refused("norm act names a stale authority epoch"));
        }
        Ok(())
    }

    fn check_ledger(&self, ledger: &str) -> StoreResult<()> {
        if ledger != self.ledger {
            return Err(refused("norm act targets another ledger/charter"));
        }
        Ok(())
    }
}

/// Replay a complete admitted history, independent of transport order. This
/// slice refuses competing record heads, instead of choosing an import-order
/// winner. Rotation closes the exact old-epoch frontier. Evidence-conflict
/// interpretation remains a separate tracker obligation.
pub fn replay_norm(
    events: &[TrackerEvent],
    checkpoint: &NormCheckpoint,
    verifier: &dyn NormVerifier,
) -> StoreResult<NormView> {
    let expected_ledger = &checkpoint.ledger;
    let mut unique = BTreeMap::new();
    for event in events {
        if !event.kind.starts_with("norm.") {
            continue;
        }
        if let Some(prior) = unique.insert(event.event_id.clone(), event) {
            if prior != event {
                return Err(refused(
                    "norm event identity has conflicting transport bytes",
                ));
            }
        }
    }
    let genesis = unique.remove(expected_ledger).ok_or_else(|| {
        StoreError::Conflict("pinned norm genesis is missing; recover the original evidence".into())
    })?;
    let mut view = NormView::bootstrap(genesis, verifier)?;
    let mut seen = std::collections::BTreeSet::from([expected_ledger.to_owned()]);
    while !unique.is_empty() {
        let Some((ready, event)) = unique
            .iter()
            .find(|(_, event)| event.parents.iter().all(|parent| seen.contains(parent)))
            .map(|(id, event)| (id.clone(), *event))
        else {
            // The negative control treats a partial prefix as complete history.
            // MUTATION-SUCCESS-EXPR: Ok(view)
            return Err(refused("norm history has missing parents or a cycle"));
        };
        unique.remove(&ready);
        view.apply(event, verifier)?;
        seen.insert(ready);
    }
    if !view.authority_history.contains(&checkpoint.authority_head) {
        return Err(refused(
            "pinned authority checkpoint is missing; recover its succession evidence",
        ));
    }
    Ok(view)
}

/// Opaque incremental preparation under the same verifier and interpreter as
/// ordinary admission. It owns its verified projection; callers cannot inject
/// projected state. Publication still has to compare the captured host basis.
pub struct NormPreparation<'a> {
    view: NormView,
    verifier: &'a dyn NormVerifier,
    events: BTreeMap<String, TrackerEvent>,
}
impl<'a> NormPreparation<'a> {
    pub fn new(
        history: &[TrackerEvent],
        checkpoint: &NormCheckpoint,
        verifier: &'a dyn NormVerifier,
    ) -> StoreResult<Self> {
        Ok(Self {
            view: replay_norm(history, checkpoint, verifier)?,
            verifier,
            events: history
                .iter()
                .filter(|e| e.kind.starts_with("norm."))
                .map(|e| (e.event_id.clone(), e.clone()))
                .collect(),
        })
    }
    pub fn view(&self) -> &NormView {
        &self.view
    }
    /// Check current admission premises, exact signature/nonce and complete
    /// causal parents before applying the ordinary interpreter once.
    pub fn admit(&mut self, event: &TrackerEvent) -> StoreResult<()> {
        if let Some(prior) = self.events.get(&event.event_id) {
            return if prior == event {
                Ok(())
            } else {
                Err(refused(
                    "norm event identity has conflicting transport bytes",
                ))
            };
        }
        if event
            .parents
            .iter()
            .any(|parent| !self.events.contains_key(parent))
        {
            return Err(refused("norm preparation has missing causal parents"));
        }
        self.view.check_admission_premises(event, self.verifier)?;
        let mut next = self.view.clone();
        next.apply(event, self.verifier)?;
        self.view = next;
        self.events.insert(event.event_id.clone(), event.clone());
        Ok(())
    }
}

/// A validated candidate and expected pin, prepared under the host transaction.
/// Replaying all existing events also ensures that a partial/corrupt import can
/// never become usable authority merely because the next request is well formed.
pub fn admit_norm(
    existing: &[TrackerEvent],
    pin: Option<&NormCheckpoint>,
    event: &TrackerEvent,
    verifier: &dyn NormVerifier,
) -> StoreResult<NormView> {
    let initial = NormCheckpoint::genesis(event.event_id.clone());
    let expected = pin.unwrap_or(&initial);
    // What the new act must bind is judged against everything the ledger holds
    // now; the replay below judges it against its causal past.
    if let Some(pin) = pin {
        if existing.iter().any(|prior| prior.kind.starts_with("norm.")) {
            replay_norm(existing, pin, verifier)?.check_admission_premises(event, verifier)?;
        }
    }
    let mut all = existing.to_vec();
    all.push(event.clone());
    let view = replay_norm(&all, expected, verifier)?;
    if pin.is_none() {
        verifier
            .authorize_creation(&view.creator, &view.owner)
            .map_err(refused)?;
    }
    Ok(view)
}

#[cfg(test)]
mod reference_projection_tests {
    use super::*;

    struct TrustedFixture;

    impl NormVerifier for TrustedFixture {
        fn verify(
            &self,
            _actor: &NormActor,
            _signing_bytes: &[u8],
            _signature: &str,
        ) -> Result<(), String> {
            Ok(())
        }

        fn authorize_creation(&self, _creator: &str, _owner: &NormActor) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn historical_edge_projection_refuses_corrupt_observed_acts() {
        let signed = SignedNormEvent {
            statement: NormStatement {
                protocol: "whipplescript.norm/v1".into(),
                actor: NormActor {
                    principal: "owner".into(),
                    algorithm: "p256-sha256".into(),
                    key_id: "fixture".into(),
                },
                nonce: "genesis".into(),
                created_at: "2026-09-05T00:00:00Z".into(),
                action: NormAct::Bootstrap {
                    creator: "worker".into(),
                    charter: NormCharter::bundled().unwrap(),
                },
                premises: None,
            },
            signature: "fixture".into(),
            successor_signature: None,
        };
        let genesis = signed.tracker_event().unwrap();
        let mut view = NormView::bootstrap(&genesis, &TrustedFixture).unwrap();
        let vocabulary = Vocabulary::new(
            view.charter
                .vocabularies
                .iter()
                .find(|entry| entry.definition.name == "refines")
                .unwrap()
                .definition
                .clone(),
        )
        .unwrap()
        .reference()
        .clone();
        let record = NormRecord {
            id: "relation".into(),
            vocabulary,
            fields: serde_json::json!({"source":"missing", "target":"missing"}),
            content_head: "revision".into(),
            status: "proposed".into(),
            head: "act".into(),
        };
        let act = RecordAct {
            event: "act".into(),
            charter_event: genesis.event_id,
            record: record.clone(),
            effective: None,
        };
        view.record_acts.insert(record.id.clone(), vec![act]);
        let historical = crate::norm_reference_inventory::observed_admission_edges_at(&view)
            .expect("historical identity references do not require a current provider");
        assert_eq!(historical.references.len(), 2);
        assert!(historical.references.iter().all(|reference| {
            reference.provider == "missing"
                && reference.resolution
                    == crate::norm_reference_inventory::NormHistoricalResolution::IdentityRevisionUnknown
        }));
        let refuses = |view: &NormView, message: &str| {
            let error = crate::norm_reference_inventory::observed_admission_edges_at(view)
                .expect_err("corrupt historical act must refuse");
            assert!(format!("{error:?}").contains(message), "{error:?}");
        };
        let mut unknown = view.clone();
        unknown.record_acts.get_mut("relation").unwrap()[0]
            .record
            .vocabulary
            .name = "unadmitted".into();
        refuses(
            &unknown,
            "historical norm act has no admitted vocabulary interpretation",
        );
        let mut non_object = view.clone();
        non_object.record_acts.get_mut("relation").unwrap()[0]
            .record
            .fields = serde_json::json!(42);
        refuses(
            &non_object,
            "historical norm record fields are not an object",
        );
        let mut missing_required = view.clone();
        missing_required.record_acts.get_mut("relation").unwrap()[0]
            .record
            .fields = serde_json::json!({"target":"missing"});
        refuses(
            &missing_required,
            "historical norm record lacks a required declared field",
        );

        view.records.insert(record.id.clone(), record);
        let error = crate::norm_reference_inventory::observed_edges_at(&view)
            .expect_err("current identity target is missing");
        assert!(
            format!("{error:?}").contains("norm identity reference does not resolve"),
            "{error:?}"
        );
    }
}
