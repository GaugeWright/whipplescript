//! Atomic attributed governance-history import (DR-0292). Source provenance is
//! not governance authority: only ordinary authenticated norm acts install it.
use crate::items::TrackerEvent;
use crate::norm::{
    NormAct, NormActor, NormCheckpoint, NormPreparation, NormStatement, NormVerifier, NormView,
    SignedNormEvent,
};
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PROTOCOL: &str = "whipplescript.norm.governance-import/v1";
const MAX_SOURCE: usize = 16 * 1024 * 1024;
const MAX_EVENTS: usize = 50_000;
fn source_digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn refuse(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceDestination {
    pub ledger: String,
    pub authority: String,
    pub frontier: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceSource {
    pub scope: String,
    pub revision: String,
    pub path: String,
    pub sha256: String,
    pub raw_base64: String,
    pub event_count: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceMapping {
    pub number: String,
    pub record: String,
    pub source_event_indices: Vec<usize>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceChronology {
    pub index: usize,
    pub decision_number: String,
    pub source_state: String,
    pub raw_parsed_event: Value,
    pub representation: String,
    pub reason: String,
    pub effective_event: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceAdoption {
    pub decision: String,
    pub adoption_event: String,
    pub mode: String,
    pub source_indices: Vec<usize>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceDescriptor {
    pub protocol: String,
    pub import_id: String,
    pub destination: GovernanceDestination,
    pub source: GovernanceSource,
    pub mapping: Vec<GovernanceMapping>,
    pub chronology: Vec<GovernanceChronology>,
    pub adoptions: Vec<GovernanceAdoption>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernanceImportRequest {
    pub descriptor: GovernanceDescriptor,
    pub events: Vec<TrackerEvent>,
    pub descriptor_record: String,
    pub descriptor_active: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceImportResult {
    pub descriptor_record: String,
    pub descriptor_active: String,
    pub mapping: Vec<GovernanceMapping>,
    pub admitted: usize,
    pub replayed: bool,
}

impl<'de> Deserialize<'de> for GovernanceImportRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            descriptor: GovernanceDescriptor,
            events: Vec<TrackerEvent>,
            descriptor_record: String,
            descriptor_active: String,
        }
        let Unique(value) = Unique::deserialize(d)?;
        let w: Wire = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            descriptor: w.descriptor,
            events: w.events,
            descriptor_record: w.descriptor_record,
            descriptor_active: w.descriptor_active,
        })
    }
}

// Value's usual map decoder silently replaces duplicate fields. This recursive
// visitor rejects duplicates before typed decoding, including nested source data.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a value with unique object fields")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| Unique(Value::Number(v)))
                    .ok_or_else(|| E::custom("non-finite source number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Unique, E> {
                self.visit_unit()
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if values.contains_key(&k) {
                        return Err(serde::de::Error::custom(format!("duplicate field {k}")));
                    }
                    values.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub fn decode_request(raw: &str) -> StoreResult<GovernanceImportRequest> {
    if raw.len() > MAX_SOURCE * 4 {
        return Err(refuse("governance request exceeds the admission limit"));
    }
    let unique: Unique = serde_json::from_str(raw)?;
    Ok(serde_json::from_value(unique.0)?)
}
fn source_events(raw: &[u8]) -> StoreResult<Vec<Value>> {
    if raw.len() > MAX_SOURCE {
        return Err(refuse("governance source exceeds the admission limit"));
    }
    let Unique(value) = deser_hjson::from_slice(raw)
        .map_err(|e| refuse(format!("invalid complete governance source: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| refuse("governance source must be an object"))?;
    if object.get("schemaVersion") != Some(&json!(1))
        || object.keys().any(|k| k != "schemaVersion" && k != "events")
    {
        return Err(refuse("unsupported governance source schema"));
    }
    let events = object
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("governance source has no chronology"))?;
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(refuse("governance source chronology size is unsupported"));
    }
    for event in events {
        let number = event
            .get("decisionId")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("source decision number is missing"))?;
        if !number.starts_with("DR-")
            || number.len() != 7
            || !number[3..].bytes().all(|b| b.is_ascii_digit())
            || event
                .get("state")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(refuse("source decision number/state is malformed"));
        }
    }
    Ok(events.clone())
}
impl GovernanceSource {
    pub fn from_bytes(
        scope: String,
        revision: String,
        path: String,
        raw: &[u8],
    ) -> StoreResult<Self> {
        let event_count = source_events(raw)?.len();
        Ok(Self {
            scope,
            revision,
            path,
            sha256: source_digest(raw),
            raw_base64: crate::bundle::encode_base64(raw),
            event_count,
        })
    }
    /// Revalidate the exact raw document and return its complete attributed rows.
    /// This establishes source identity, never actor or adoption authority.
    pub fn events(&self) -> StoreResult<Vec<Value>> {
        if self.scope.trim().is_empty()
            || self.path.trim().is_empty()
            || self.revision.trim().is_empty()
        {
            return Err(refuse("governance source provenance is incomplete"));
        }
        if self.raw_base64.len() > MAX_SOURCE.div_ceil(3) * 4 {
            return Err(refuse("governance source exceeds the admission limit"));
        }
        let raw = crate::bundle::decode_base64(&self.raw_base64).map_err(refuse)?;
        if crate::bundle::encode_base64(&raw) != self.raw_base64
            || source_digest(&raw) != self.sha256
        {
            return Err(refuse(
                "governance source digest/encoding does not match original bytes",
            ));
        }
        let events = source_events(&raw)?;
        if events.len() != self.event_count {
            return Err(refuse("governance source event count is not complete"));
        }
        Ok(events)
    }
}
impl GovernanceDescriptor {
    pub fn canonical_json(&self) -> StoreResult<String> {
        Ok(serde_json::to_string(self)?)
    }
    pub fn validate(&self) -> StoreResult<()> {
        if self.protocol != PROTOCOL || self.import_id.trim().is_empty() {
            return Err(refuse("invalid governance import identity/protocol"));
        }
        NormCheckpoint {
            ledger: self.destination.ledger.clone(),
            authority_head: self.destination.authority.clone(),
        }
        .validate()?;
        let frontier: BTreeSet<_> = self.destination.frontier.iter().collect();
        if frontier.is_empty() || frontier.len() != self.destination.frontier.len() {
            return Err(refuse(
                "governance starting frontier is missing or duplicated",
            ));
        }
        let events = self.source.events()?;
        if events.len() != self.chronology.len() {
            return Err(refuse("governance chronology omits source rows"));
        }
        let mut indices: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, (event, row)) in events.iter().zip(&self.chronology).enumerate() {
            if row.index != index
                || row.raw_parsed_event != *event
                || event.get("decisionId").and_then(Value::as_str)
                    != Some(row.decision_number.as_str())
                || event.get("state").and_then(Value::as_str) != Some(row.source_state.as_str())
                || row.representation != "attributed_only"
                || row.reason.trim().is_empty()
                || row.effective_event.is_some()
            {
                return Err(refuse("governance chronology changed/reordered source content or claims historical approval"));
            }
            indices
                .entry(row.decision_number.clone())
                .or_default()
                .push(index);
        }
        let mut records = BTreeSet::new();
        let mut numbers = BTreeSet::new();
        for mapping in &self.mapping {
            if !numbers.insert(&mapping.number)
                || !records.insert(&mapping.record)
                || indices.get(&mapping.number) != Some(&mapping.source_event_indices)
            {
                return Err(refuse("governance mapping is conflicting or incomplete"));
            }
        }
        if numbers.len() != indices.len() {
            return Err(refuse("governance mapping omits a source decision"));
        }
        let mut adopted = BTreeSet::new();
        for a in &self.adoptions {
            let mapped = self
                .mapping
                .iter()
                .find(|m| m.record == a.decision)
                .ok_or_else(|| refuse("adoption names an unmapped decision"))?;
            if a.mode != "explicit_adoption_now"
                || !adopted.insert(&a.decision)
                || a.source_indices.is_empty()
                || a.source_indices
                    .iter()
                    .any(|i| !mapped.source_event_indices.contains(i))
            {
                return Err(refuse(
                    "governance adoption is not exact explicit adoption now",
                ));
            }
        }
        Ok(())
    }
}

/// Immutable original descriptor installed by its first authenticated activation.
/// Latest public fields and retirement never determine this migration map.
#[derive(Clone, Debug)]
struct Installation {
    descriptor: GovernanceDescriptor,
    record: String,
    active: String,
}
fn descriptor_at_creation(
    view: &NormView,
    record: &str,
) -> StoreResult<Option<GovernanceDescriptor>> {
    let Some(revision) = view.revision(record) else {
        return Ok(None);
    };
    if revision.vocabulary.name != "assertion" || revision.vocabulary.version != "1" {
        return Ok(None);
    }
    let Some(statement) = revision.fields.get("statement").and_then(Value::as_str) else {
        return Ok(None);
    };
    let unique: Unique = match serde_json::from_str(statement) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let Some(protocol) = unique.0.get("protocol").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !protocol.starts_with("whipplescript.norm.governance-import/") {
        return Ok(None);
    }
    if protocol != PROTOCOL {
        return Err(refuse("unsupported retained governance import protocol"));
    }
    let descriptor: GovernanceDescriptor = serde_json::from_value(unique.0)?;
    descriptor.validate()?;
    if statement != descriptor.canonical_json()?
        || revision.fields.get("title").and_then(Value::as_str)
            != Some(descriptor.import_id.as_str())
        || revision.fields.get("subject").and_then(Value::as_str)
            != Some(descriptor.source.scope.as_str())
    {
        return Err(refuse(
            "governance descriptor fields are not exact canonical import data",
        ));
    }
    Ok(Some(descriptor))
}
fn expected_ids(
    descriptor: &GovernanceDescriptor,
    record: &str,
    active: &str,
) -> StoreResult<BTreeSet<String>> {
    let mut ids: BTreeSet<_> = descriptor
        .mapping
        .iter()
        .map(|m| m.record.clone())
        .collect();
    for adoption in &descriptor.adoptions {
        if !ids.insert(adoption.adoption_event.clone()) {
            return Err(refuse("governance event roster repeats an identity"));
        }
    }
    if !ids.insert(record.into()) || !ids.insert(active.into()) {
        return Err(refuse(
            "governance descriptor identities collide with content",
        ));
    }
    Ok(ids)
}
fn verify_roster(
    descriptor: &GovernanceDescriptor,
    record: &str,
    active: &str,
    events: &[TrackerEvent],
    view: &NormView,
) -> StoreResult<()> {
    let by_id: BTreeMap<_, _> = events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    if by_id.len() != events.len() {
        return Err(refuse(
            "governance event roster has duplicate transport identities",
        ));
    }
    for id in expected_ids(descriptor, record, active)? {
        if !by_id.contains_key(id.as_str()) {
            return Err(refuse("retained governance event roster is incomplete"));
        }
    }
    for mapping in &descriptor.mapping {
        let event = by_id
            .get(mapping.record.as_str())
            .ok_or_else(|| refuse("mapped decision event is missing"))?;
        let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
        if !matches!(&signed.statement.action,NormAct::Create{ledger,vocabulary,..} if ledger==&descriptor.destination.ledger && vocabulary.name=="decision" && vocabulary.version=="1")
            || view
                .revision(&mapping.record)
                .is_none_or(|r| r.status != "proposed" || r.content_head != mapping.record)
        {
            return Err(refuse(
                "governance mapping must name an ordinary proposed decision creation",
            ));
        }
    }
    for mapping in &descriptor.mapping {
        let revision = view
            .revision(&mapping.record)
            .ok_or_else(|| refuse("mapped decision revision is unavailable"))?;
        let rows: Vec<_> = mapping
            .source_event_indices
            .iter()
            .map(|i| descriptor.chronology[*i].raw_parsed_event.clone())
            .collect();
        if revision.fields
            != decision_fields(
                view,
                &revision.vocabulary,
                &descriptor.source,
                &mapping.number,
                &rows,
            )?
        {
            return Err(refuse(
                "mapped decision content does not faithfully represent source chronology",
            ));
        }
    }
    let creation = by_id
        .get(record)
        .ok_or_else(|| refuse("descriptor creation is unavailable"))?;
    let signed_creation: SignedNormEvent = serde_json::from_str(&creation.payload_json)?;
    let mut references: Vec<_> = descriptor
        .mapping
        .iter()
        .map(|m| m.record.clone())
        .chain(
            descriptor
                .adoptions
                .iter()
                .map(|a| a.adoption_event.clone()),
        )
        .collect();
    references.sort();
    let mut bound = signed_creation
        .statement
        .premises
        .as_ref()
        .map(|p| p.references.clone())
        .unwrap_or_default();
    bound.sort();
    if references != bound {
        return Err(refuse(
            "governance descriptor did not bind its exact content/adoption roster",
        ));
    }
    for adoption in &descriptor.adoptions {
        let event = by_id
            .get(adoption.adoption_event.as_str())
            .ok_or_else(|| refuse("adoption evidence is missing"))?;
        let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
        if !matches!(&signed.statement.action,NormAct::Transition{record,previous,status,..} if record==&adoption.decision && previous==record && status=="accepted")
        {
            return Err(refuse(
                "governance adoption is not ordinary exact-content acceptance",
            ));
        }
    }
    let event = by_id
        .get(active)
        .ok_or_else(|| refuse("governance activation is missing"))?;
    let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
    if !matches!(&signed.statement.action,NormAct::Transition{record:r,previous,status,..} if r==record && previous==record && status=="active")
    {
        return Err(refuse(
            "governance activation does not pin original descriptor revision",
        ));
    }
    if descriptor_at_creation(view, record)?.as_ref() != Some(descriptor) {
        return Err(refuse("signed descriptor does not match import request"));
    }
    Ok(())
}
fn installations(history: &[TrackerEvent], view: &NormView) -> StoreResult<Vec<Installation>> {
    let by_id: BTreeMap<_, _> = history.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let mut installed = BTreeSet::new();
    let mut result = Vec::new();
    for id in view.event_order() {
        let Some(event) = by_id.get(id.as_str()) else {
            return Err(refuse("verified governance history is unavailable"));
        };
        let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
        let NormAct::Transition {
            record,
            previous,
            status,
            ..
        } = signed.statement.action
        else {
            continue;
        };
        if status != "active" || installed.contains(&record) {
            continue;
        }
        let Some(descriptor) = descriptor_at_creation(view, &record)? else {
            continue;
        };
        if previous != record {
            return Err(refuse(
                "governance installation substituted descriptor revision before activation",
            ));
        }
        verify_roster(&descriptor, &record, id, history, view)?;
        installed.insert(record.clone());
        result.push(Installation {
            descriptor,
            record,
            active: id.clone(),
        });
    }
    // Fail closed even when a caller installed a competing carrier through
    // ordinary assertion authoring rather than this dedicated importer.
    let mut bindings = BTreeMap::new();
    let mut invocations = BTreeMap::new();
    for installation in &result {
        let descriptor = &installation.descriptor;
        let key = (
            descriptor.source.scope.clone(),
            descriptor.import_id.clone(),
        );
        if invocations.insert(key, descriptor).is_some() {
            return Err(refuse(
                "governance import invocation has competing historical installations",
            ));
        }
        for mapping in &descriptor.mapping {
            let key = (descriptor.source.scope.clone(), mapping.number.clone());
            if bindings
                .insert(key, &mapping.record)
                .is_some_and(|old| old != &mapping.record)
            {
                return Err(refuse(
                    "governance source number has conflicting historical bindings",
                ));
            }
        }
    }
    Ok(result)
}
/// Reconstruct migration data from complete verified history, never latest
/// carrier fields. The caller must already hold full-ledger read authority.
pub fn resolve_governance_reference(
    history: &[TrackerEvent],
    checkpoint: &NormCheckpoint,
    verifier: &dyn NormVerifier,
    scope: &str,
    number: &str,
) -> StoreResult<Option<String>> {
    let view = crate::norm::replay_norm(history, checkpoint, verifier)?;
    Ok(installations(history, &view)?
        .iter()
        .filter(|i| i.descriptor.source.scope == scope)
        .flat_map(|i| &i.descriptor.mapping)
        .find(|m| m.number == number)
        .map(|m| m.record.clone()))
}
/// Prepared inside the host publication boundary. Rows are already ordered by
/// the ordinary interpreter; the host publishes these exact bytes atomically.
pub struct ValidatedGovernanceImport {
    pub events: Vec<TrackerEvent>,
    pub result: GovernanceImportResult,
}
pub fn validate_import(
    history: &[TrackerEvent],
    checkpoint: &NormCheckpoint,
    request: &GovernanceImportRequest,
    verifier: &dyn NormVerifier,
) -> StoreResult<ValidatedGovernanceImport> {
    request.descriptor.validate()?;
    let expected = expected_ids(
        &request.descriptor,
        &request.descriptor_record,
        &request.descriptor_active,
    )?;
    if request.events.len() != expected.len()
        || request
            .events
            .iter()
            .map(|e| e.event_id.clone())
            .collect::<BTreeSet<_>>()
            != expected
    {
        return Err(refuse(
            "governance request event roster has extra or omitted acts",
        ));
    }
    let mut preparation = NormPreparation::new(history, checkpoint, verifier)?;
    let retained = installations(history, preparation.view())?;
    if let Some(prior) = retained.iter().find(|i| {
        i.descriptor.source.scope == request.descriptor.source.scope
            && i.descriptor.import_id == request.descriptor.import_id
    }) {
        if prior.descriptor != request.descriptor
            || prior.record != request.descriptor_record
            || prior.active != request.descriptor_active
        {
            return Err(refuse(
                "governance retry altered the original descriptor/install identities",
            ));
        }
        let by_id: BTreeMap<_, _> = history.iter().map(|e| (e.event_id.as_str(), e)).collect();
        if request
            .events
            .iter()
            .any(|e| by_id.get(e.event_id.as_str()).copied() != Some(e))
        {
            return Err(refuse(
                "governance retry did not retain exact admitted signed envelopes",
            ));
        }
        return Ok(ValidatedGovernanceImport {
            events: Vec::new(),
            result: GovernanceImportResult {
                descriptor_record: prior.record.clone(),
                descriptor_active: prior.active.clone(),
                mapping: prior.descriptor.mapping.clone(),
                admitted: 0,
                replayed: true,
            },
        });
    }
    let view = preparation.view();
    if request.descriptor.destination.ledger != view.ledger
        || request.descriptor.destination.authority != view.authority_head
        || request
            .descriptor
            .destination
            .frontier
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != view.frontier
    {
        return Err(refuse(
            "governance first admission has a stale destination basis",
        ));
    }
    for prior in &retained {
        if prior.descriptor.source.scope == request.descriptor.source.scope
            && prior.descriptor.mapping.iter().any(|old| {
                request
                    .descriptor
                    .mapping
                    .iter()
                    .any(|new| new.number == old.number && new.record != old.record)
            })
        {
            return Err(refuse(
                "governance import would remap an installed source number",
            ));
        }
    }
    // A partial prior admission is never filled in under first-admission rules.
    if history.iter().any(|e| expected.contains(&e.event_id)) {
        return Err(refuse(
            "governance first admission has partial retained import evidence",
        ));
    }
    let mut pending: BTreeMap<_, _> = request
        .events
        .iter()
        .map(|e| (e.event_id.clone(), e.clone()))
        .collect();
    let mut seen: BTreeSet<_> = history.iter().map(|e| e.event_id.clone()).collect();
    let mut ordered = Vec::new();
    while !pending.is_empty() {
        let Some(id) = pending
            .iter()
            .find(|(_, e)| e.parents.iter().all(|p| seen.contains(p)))
            .map(|(id, _)| id.clone())
        else {
            return Err(refuse(
                "governance import has missing causal parents or a cycle",
            ));
        };
        let event = pending
            .remove(&id)
            .ok_or_else(|| refuse("governance preparation lost an event"))?;
        preparation.admit(&event)?;
        seen.insert(id);
        ordered.push(event);
    }
    verify_roster(
        &request.descriptor,
        &request.descriptor_record,
        &request.descriptor_active,
        &ordered,
        preparation.view(),
    )?;
    let mut combined = history.to_vec();
    combined.extend(ordered.iter().cloned());
    installations(&combined, preparation.view())?;
    Ok(ValidatedGovernanceImport {
        result: GovernanceImportResult {
            descriptor_record: request.descriptor_record.clone(),
            descriptor_active: request.descriptor_active.clone(),
            mapping: request.descriptor.mapping.clone(),
            admitted: ordered.len(),
            replayed: false,
        },
        events: ordered,
    })
}

/// Explicit exact installed declarations; names alone do not select a schema.
pub struct GovernancePreparationOptions {
    pub import_id: String,
    pub source: GovernanceSource,
    pub actor: NormActor,
    pub created_at: String,
    pub nonce_prefix: String,
    pub decision_vocabulary: whipplescript_core::vocabulary::VocabularyRef,
    pub assertion_vocabulary: whipplescript_core::vocabulary::VocabularyRef,
    /// Empty means attribution only. Every named adoption is an ordinary new
    /// authenticated acceptance, never a translation of a source state string.
    pub adopt_numbers: Vec<String>,
}
fn decision_fields(
    view: &NormView,
    vocabulary: &whipplescript_core::vocabulary::VocabularyRef,
    source: &GovernanceSource,
    number: &str,
    rows: &[Value],
) -> StoreResult<Value> {
    let declaration = view
        .interpretation(vocabulary)
        .ok_or_else(|| refuse("governance decision declaration is not installed"))?;
    if vocabulary.name != "decision"
        || vocabulary.version != "1"
        || declaration.definition.status.initial != "proposed"
    {
        return Err(refuse("unsupported governance decision declaration"));
    }
    let names: BTreeSet<_> = declaration
        .definition
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    let text = serde_json::to_string(rows)?;
    let bundled = BTreeSet::from(["title", "intent", "subjects", "supersedes"]);
    let engineering = BTreeSet::from([
        "title",
        "question",
        "course",
        "rationale",
        "alternatives",
        "scope",
        "consequences",
        "subjects",
        "supersedes",
    ]);
    if names == bundled {
        Ok(json!({"title":format!("Imported {number}"),"intent":text,"subjects":[source.scope]}))
    } else if names == engineering {
        Ok(
            json!({"title":format!("Imported {number}"),"question":"Attributed governance source decision","course":text,"rationale":"Source chronology is content, not authenticated historical acceptance.","scope":source.scope,"consequences":"Any destination adoption is a separate ordinary authenticated act.","subjects":[source.scope]}),
        )
    } else {
        Err(refuse(
            "unsupported closed governance decision field mapping",
        ))
    }
}
fn validate_assertion(
    view: &NormView,
    vocabulary: &whipplescript_core::vocabulary::VocabularyRef,
) -> StoreResult<()> {
    let declaration = view
        .interpretation(vocabulary)
        .ok_or_else(|| refuse("governance assertion declaration is not installed"))?;
    if vocabulary.name != "assertion"
        || vocabulary.version != "1"
        || declaration
            .definition
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["title", "statement", "subject"])
        || declaration.definition.status.initial != "proposed"
    {
        return Err(refuse(
            "unsupported closed governance assertion field mapping",
        ));
    }
    Ok(())
}
/// Capture/read once and incrementally stage ordinary verified acts, append nothing.
/// Validation reparses the source, and failure-safe staging clones its view;
/// neither operation is a per-act host snapshot or full-history replay.
/// Signing remains the installed host's responsibility. A signer cannot replace
/// the prepared statement, and no source actor is retried as a synthetic owner.
pub fn prepare_governance_import(
    history: &[TrackerEvent],
    checkpoint: &NormCheckpoint,
    verifier: &dyn NormVerifier,
    options: GovernancePreparationOptions,
    signer: &mut dyn FnMut(&NormStatement) -> StoreResult<SignedNormEvent>,
) -> StoreResult<GovernanceImportRequest> {
    prepare_from_capture(
        NormPreparation::new(history, checkpoint, verifier)?,
        options,
        signer,
    )
}
/// Continue an opaque verified capture without replaying its history again.
pub fn prepare_from_capture(
    mut preparation: NormPreparation<'_>,
    options: GovernancePreparationOptions,
    signer: &mut dyn FnMut(&NormStatement) -> StoreResult<SignedNormEvent>,
) -> StoreResult<GovernanceImportRequest> {
    validate_assertion(preparation.view(), &options.assertion_vocabulary)?;
    let source_rows = options.source.events()?;
    let destination = GovernanceDestination {
        ledger: preparation.view().ledger.clone(),
        authority: preparation.view().authority_head.clone(),
        frontier: preparation.view().frontier.iter().cloned().collect(),
    };
    let mut events = Vec::new();
    let mut mappings: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut chronology = Vec::new();
    for (index, row) in source_rows.iter().enumerate() {
        let number = row["decisionId"]
            .as_str()
            .ok_or_else(|| refuse("source decision number is missing"))?
            .to_owned();
        mappings.entry(number.clone()).or_default().push(index);
        chronology.push(GovernanceChronology{index,decision_number:number,source_state:row["state"].as_str().ok_or_else(||refuse("source state is missing"))?.into(),raw_parsed_event:row.clone(),representation:"attributed_only".into(),reason:"No original destination-authenticated approval; source lifecycle retained as attributed content.".into(),effective_event:None});
    }
    let initial = preparation.view().clone();
    let mut stage = |action: NormAct,
                     nonce: String,
                     premises: Option<crate::norm::NormPremises>|
     -> StoreResult<TrackerEvent> {
        let statement = NormStatement {
            protocol: "whipplescript.norm/v1".into(),
            actor: options.actor.clone(),
            nonce,
            created_at: options.created_at.clone(),
            action,
            premises,
        };
        let signed = signer(&statement)?;
        if signed.statement != statement {
            return Err(refuse(
                "governance signer substituted the prepared statement",
            ));
        }
        let event = signed.tracker_event()?;
        preparation.admit(&event)?;
        events.push(event.clone());
        Ok(event)
    };
    // Field mapping needs the verified initial charter, which is unchanged by
    // these create/transition acts. Resolve before the staging closure borrows it.
    let mut mapping = Vec::new();
    for (number, indices) in &mappings {
        let rows: Vec<_> = indices.iter().map(|i| source_rows[*i].clone()).collect();
        let fields = decision_fields(
            &initial,
            &options.decision_vocabulary,
            &options.source,
            number,
            &rows,
        )?;
        let event = stage(
            NormAct::Create {
                ledger: destination.ledger.clone(),
                authority: Some(destination.authority.clone()),
                vocabulary: options.decision_vocabulary.clone(),
                fields_json: serde_json::to_string(&fields)?,
            },
            format!("{}:decision:{number}", options.nonce_prefix),
            None,
        )?;
        mapping.push(GovernanceMapping {
            number: number.clone(),
            record: event.event_id,
            source_event_indices: indices.clone(),
        });
    }
    let mut adoptions = Vec::new();
    let mut adopted = BTreeSet::new();
    for number in &options.adopt_numbers {
        if !adopted.insert(number) {
            return Err(refuse("governance preparation repeats explicit adoption"));
        }
        let mapped = mapping
            .iter()
            .find(|m| &m.number == number)
            .ok_or_else(|| refuse("explicit adoption names an absent source decision"))?;
        let event = stage(
            NormAct::Transition {
                ledger: destination.ledger.clone(),
                authority: Some(destination.authority.clone()),
                vocabulary: options.decision_vocabulary.clone(),
                record: mapped.record.clone(),
                previous: mapped.record.clone(),
                status: "accepted".into(),
            },
            format!("{}:adopt:{number}", options.nonce_prefix),
            None,
        )?;
        adoptions.push(GovernanceAdoption {
            decision: mapped.record.clone(),
            adoption_event: event.event_id,
            mode: "explicit_adoption_now".into(),
            source_indices: mapped.source_event_indices.clone(),
        });
    }
    let descriptor = GovernanceDescriptor {
        protocol: PROTOCOL.into(),
        import_id: options.import_id,
        destination: destination.clone(),
        source: options.source,
        mapping,
        chronology,
        adoptions,
    };
    descriptor.validate()?;
    let references: Vec<_> = descriptor
        .mapping
        .iter()
        .map(|m| m.record.clone())
        .chain(
            descriptor
                .adoptions
                .iter()
                .map(|a| a.adoption_event.clone()),
        )
        .collect();
    let record=stage(NormAct::Create{ledger:destination.ledger.clone(),authority:Some(destination.authority.clone()),vocabulary:options.assertion_vocabulary.clone(),fields_json:json!({"title":descriptor.import_id,"subject":descriptor.source.scope,"statement":descriptor.canonical_json()?}).to_string()},format!("{}:descriptor",options.nonce_prefix),Some(crate::norm::NormPremises{family_basis:None,references,inventory_frontier:Vec::new()}))?;
    let active = stage(
        NormAct::Transition {
            ledger: destination.ledger,
            authority: Some(destination.authority),
            vocabulary: options.assertion_vocabulary,
            record: record.event_id.clone(),
            previous: record.event_id.clone(),
            status: "active".into(),
        },
        format!("{}:install", options.nonce_prefix),
        None,
    )?;
    Ok(GovernanceImportRequest {
        descriptor,
        events,
        descriptor_record: record.event_id,
        descriptor_active: active.event_id,
    })
}

#[cfg(all(test, feature = "native"))]
mod tests;
