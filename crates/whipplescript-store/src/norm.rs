//! Authenticated norm-ledger events (DR-0098, V0).
//!
//! C0 is immutable in this slice. Every event pins its genesis/charter and exact
//! vocabulary. This module verifies and interprets events; host stores own the
//! atomic transaction that checks the persisted pin and appends the result.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_core::vocabulary::{
    AdmissionPredicate, ReferenceForm, ValueType, Vocabulary, VocabularyDefinition, VocabularyRef,
    VocabularyRegistry,
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
    /// Named scopes delegated to the authenticated governance owner by C0.
    pub owner_scopes: Vec<String>,
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
    effective_lifecycles: BTreeMap<String, EffectiveLifecycle>,
    /// Every content revision ever admitted, by its revision id, so a revision
    /// reference resolves to its record after later edits moved the head.
    revisions: BTreeMap<String, String>,
    /// The last admitted act on any record of each relation family; the basis
    /// a relation act binds. A family with no act yet has the ledger as its basis.
    family_heads: BTreeMap<String, String>,
    /// The inventory frontier each exhaustive manifest revision bound.
    manifest_bases: BTreeMap<String, Vec<String>>,
    pub authority_head: String,
    pub frontier: BTreeSet<String>,
    authority_history: BTreeSet<String>,
    event_order: Vec<String>,
    creator: String,
    registry: VocabularyRegistry,
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

fn registry_for(charter: &NormCharter) -> StoreResult<VocabularyRegistry> {
    crate::norm_resources::validate_resource_domains(charter)?;
    let mut registry = VocabularyRegistry::default();
    let mut scopes: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    for scope in &charter.owner_scopes {
        let new_scope = scopes.insert(scope);
        if scope.trim().is_empty() || !new_scope {
            return Err(refused("C0 authority scopes must be nonempty and unique"));
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
        crate::norm_correspondence::validate_correspondence_declaration(entry)?;
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
            if let AdmissionPredicate::Authority { scope } = predicate {
                if !scopes.contains(scope) {
                    return Err(refused(
                        "vocabulary references an undeclared C0 authority scope",
                    ));
                }
            }
        }
        registry
            .register(vocabulary)
            .map_err(|e| refused(e.to_string()))?;
    }
    Ok(registry)
}

impl NormView {
    fn bootstrap(event: &TrackerEvent, verifier: &dyn NormVerifier) -> StoreResult<Self> {
        let signed = verify_event(event, verifier)?;
        let NormAct::Bootstrap { creator, charter } = signed.statement.action else {
            return Err(refused("norm genesis must be a bootstrap act"));
        };
        let registry = registry_for(&charter)?;
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
            manifest_bases: BTreeMap::new(),
            authority_head: event.event_id.clone(),
            frontier: BTreeSet::from([event.event_id.clone()]),
            authority_history: BTreeSet::from([event.event_id.clone()]),
            event_order: vec![event.event_id.clone()],
            creator,
            registry,
            nonces,
        })
    }

    fn permitted(&self, predicate: &AdmissionPredicate, actor: &NormActor) -> StoreResult<()> {
        let permitted = match predicate {
            AdmissionPredicate::Public {} => true,
            AdmissionPredicate::Authority { scope } => {
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
                self.revisions
                    .insert(event.event_id.clone(), event.event_id.clone());
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
                self.check_relation_act(
                    Some(&record),
                    &vocabulary,
                    &current.fields,
                    &status,
                    statement.premises.as_ref(),
                )?;
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
                    self.revisions
                        .insert(event.event_id.clone(), record.clone());
                }
                updated.head = event.event_id.clone();
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
        }
        // Only an admitted lifecycle act (or an explicitly activating initial
        // state) changes effectiveness. Editing never reapplies an activation.
        if event.kind == CREATE_KIND || event.kind == TRANSITION_KIND {
            let record_id = event.issue_id.as_deref().unwrap_or(&event.event_id);
            self.project_effectiveness(record_id);
        }
        for parent in &event.parents {
            self.frontier.remove(parent);
        }
        self.frontier.insert(event.event_id.clone());
        self.event_order.push(event.event_id.clone());
        self.nonces.insert(nonce, event.event_id.clone());
        Ok(())
    }

    fn effectiveness_rules(&self, record: &NormRecord) -> Option<&[EffectivenessRule]> {
        self.charter
            .vocabularies
            .iter()
            .find(|v| {
                v.definition.name == record.vocabulary.name
                    && v.definition.version == record.vocabulary.version
            })
            .and_then(|v| v.effectiveness.as_deref())
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

    fn relation_of(
        &self,
        vocabulary: &VocabularyRef,
    ) -> Option<(&NormVocabulary, &RelationDeclaration)> {
        self.charter
            .vocabularies
            .iter()
            .find(|entry| {
                entry.definition.name == vocabulary.name
                    && entry.definition.version == vocabulary.version
            })
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
            (Some(ReferenceForm::Revision), Some(reference)) => {
                self.revisions.get(reference).cloned()
            }
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
            if !relation.live_statuses.contains(&record.status) {
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
        self.charter
            .vocabularies
            .iter()
            .find(|entry| {
                entry.definition.name == vocabulary.name
                    && entry.definition.version == vocabulary.version
            })
            .and_then(|entry| entry.manifest.as_ref().map(|manifest| (entry, manifest)))
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
