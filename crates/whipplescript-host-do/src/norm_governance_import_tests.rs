// Genuine DoSqlite admission and failure rollback; no fabricated ledger projection.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::json;
use std::collections::BTreeMap;
use whipplescript_store::norm::*;
use whipplescript_store::norm_governance_import::*;
use whipplescript_store::StoreResult;

const SOURCE: &[u8] = br#"// Exact source commentary is retained by raw bytes.
{ "schemaVersion": 1, "events": [
 {"decisionId": "DR-0001", "state": "implemented", "title": "Unsupported original approval", "strange": true},
 {"decisionId": "DR-0002", "state": "superseded", "successor": "DR-0003"},
 {"decisionId": "DR-0001", "state": "rejected", "evidence": ["unverified", "original"]},
 {"decisionId": "DR-0003", "state": "proposed"}
]}"#;
struct Keys {
    keys: BTreeMap<String, SigningKey>,
}
impl Keys {
    fn new() -> Self {
        Self {
            keys: BTreeMap::from([
                (
                    "owner".into(),
                    SigningKey::from_slice(&[1; 32]).expect("owner key"),
                ),
                (
                    "outsider".into(),
                    SigningKey::from_slice(&[2; 32]).expect("outsider key"),
                ),
            ]),
        }
    }
    fn actor(&self, name: &str) -> NormActor {
        NormActor {
            principal: name.into(),
            algorithm: "p256-sha256".into(),
            key_id: hex::encode(
                self.keys[name]
                    .verifying_key()
                    .as_affine()
                    .to_sec1_point(true)
                    .as_bytes(),
            ),
        }
    }
    fn sign(&self, statement: &NormStatement) -> StoreResult<SignedNormEvent> {
        let signature: Signature =
            self.keys[&statement.actor.principal].sign(&statement.signing_bytes()?);
        Ok(SignedNormEvent {
            statement: statement.clone(),
            signature: hex::encode(signature.to_bytes()),
            successor_signature: None,
        })
    }
    fn event(&self, who: &str, nonce: &str, action: NormAct) -> SignedNormEvent {
        self.sign(&NormStatement {
            protocol: "whipplescript.norm/v1".into(),
            actor: self.actor(who),
            nonce: nonce.into(),
            created_at: "2026-10-07T00:00:00Z".into(),
            action,
            premises: None,
        })
        .expect("sign actual statement")
    }
}
impl NormVerifier for Keys {
    fn verify(&self, actor: &NormActor, bytes: &[u8], signature: &str) -> Result<(), String> {
        let key = self
            .keys
            .get(&actor.principal)
            .ok_or("unknown fixture principal")?;
        if &self.actor(&actor.principal) != actor {
            return Err("exact fixture principal/key mismatch".into());
        }
        let raw = hex::decode(signature).map_err(|e| e.to_string())?;
        let sig = Signature::from_slice(&raw).map_err(|e| e.to_string())?;
        key.verifying_key()
            .verify(bytes, &sig)
            .map_err(|e| e.to_string())
    }
    fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
        if creator == "owner" && owner == &self.actor("owner") {
            Ok(())
        } else {
            Err("fixture creation permission denied".into())
        }
    }
}
fn vocab(name: &str) -> whipplescript_core::vocabulary::VocabularyRef {
    let charter = NormCharter::bundled().expect("bundled charter");
    let definition = charter
        .vocabularies
        .into_iter()
        .find(|v| v.definition.name == name)
        .expect("installed declaration")
        .definition;
    whipplescript_core::vocabulary::Vocabulary::new(definition)
        .expect("typed declaration")
        .reference()
        .clone()
}
impl Harness {
    fn seeded() -> (Self, Keys) {
        let mut h = Self::new();
        let keys = Keys::new();
        let bootstrap = keys.event(
            "owner",
            "genesis",
            NormAct::Bootstrap {
                creator: "owner".into(),
                charter: NormCharter::bundled().expect("bundled charter"),
            },
        );
        h.append(&bootstrap, &keys)
            .expect("authenticated bootstrap");
        (h, keys)
    }
    fn prepare(
        &self,
        keys: &Keys,
        id: &str,
        who: &str,
        adopt: Vec<String>,
    ) -> StoreResult<GovernanceImportRequest> {
        let (pin, history) = self.capture();
        prepare_governance_import(
            &history,
            &pin,
            keys,
            GovernancePreparationOptions {
                import_id: id.into(),
                source: GovernanceSource::from_bytes(
                    "GaugeWright/decisions".into(),
                    "captured-revision".into(),
                    "decisions/log.hjson".into(),
                    SOURCE,
                )?,
                actor: keys.actor(who),
                created_at: "2026-10-07T00:00:00Z".into(),
                nonce_prefix: id.into(),
                decision_vocabulary: vocab("decision"),
                assertion_vocabulary: vocab("assertion"),
                adopt_numbers: adopt,
            },
            &mut |s| keys.sign(s),
        )
    }
    fn advance(&mut self, keys: &Keys, nonce: &str) {
        let (pin, _) = self.capture();
        let event = keys.event(
            "owner",
            nonce,
            NormAct::Create {
                ledger: pin.ledger,
                authority: Some(pin.authority_head),
                vocabulary: vocab("assertion"),
                fields_json:
                    json!({"title":"unrelated ordinary frontier advancement","statement":nonce})
                        .to_string(),
            },
        );
        self.append(&event, keys)
            .expect("ordinary independent append");
    }
    fn resolve(&self, keys: &Keys, number: &str) -> StoreResult<Option<String>> {
        let (pin, history) = self.capture();
        resolve_governance_reference(&history, &pin, keys, "GaugeWright/decisions", number)
    }
}
#[test]
fn whole_chronology_and_exact_retry_survive_advanced_frontier() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "whole", "owner", vec![])
        .expect("prepare real signed batch");
    assert_eq!(request.descriptor.chronology.len(), 4);
    assert_eq!(request.descriptor.chronology[0].source_state, "implemented");
    assert_eq!(request.descriptor.chronology[1].source_state, "superseded");
    assert!(request
        .descriptor
        .chronology
        .iter()
        .all(|r| r.representation == "attributed_only" && r.effective_event.is_none()));
    let first = h.import(&request, &keys).expect("atomic signed import");
    assert_eq!(first.mapping.len(), 3);
    assert!(!first.replayed);
    h.advance(&keys, "after-import");
    let before = h.capture();
    let retry = h
        .import(&request, &keys)
        .expect("exact retained retry despite moved frontier");
    assert!(retry.replayed);
    assert_eq!(retry.admitted, 0);
    assert_eq!(retry.mapping, first.mapping);
    assert_eq!(h.capture(), before);
    let mut changed = request.clone();
    changed.events[0].payload_json.push(' ');
    assert!(
        h.import(&changed, &keys).is_err(),
        "changed exact envelope must refuse"
    );
    assert_eq!(h.capture(), before);
    let mut omitted = request.clone();
    omitted.descriptor.chronology.pop();
    assert!(h.import(&omitted, &keys).is_err());
    assert_eq!(h.capture(), before);
    for m in first.mapping {
        assert_eq!(
            h.resolve(&keys, &m.number).expect("historical resolution"),
            Some(m.record)
        );
    }
}
#[test]
fn stale_first_admission_and_conflicting_mapping_never_append() {
    let (mut h, keys) = Harness::seeded();
    let first = h
        .prepare(&keys, "winner", "owner", vec![])
        .expect("first preparation");
    let racing = h
        .prepare(&keys, "racing", "owner", vec![])
        .expect("same captured basis");
    h.import(&first, &keys).expect("first wins");
    let before = h.capture();
    assert!(h.import(&racing, &keys).is_err());
    assert_eq!(h.capture(), before);
    let conflict = h
        .prepare(&keys, "fresh-conflict", "owner", vec![])
        .expect("fresh conflict preparation");
    assert!(
        h.import(&conflict, &keys).is_err(),
        "fresh basis cannot remap source names"
    );
    assert_eq!(h.capture(), before);
    let (mut independent, other) = Harness::seeded();
    let stale = independent
        .prepare(&other, "stale", "owner", vec![])
        .expect("captured preparation");
    independent.advance(&other, "before-first-import");
    let before = independent.capture();
    assert!(independent.import(&stale, &other).is_err());
    assert_eq!(independent.capture(), before);
}
#[test]
fn unauthorized_activation_and_adoption_are_not_source_approval() {
    let (h, keys) = Harness::seeded();
    let before = h.capture();
    assert!(
        h.prepare(&keys, "outside", "outsider", vec![]).is_err(),
        "outsider has valid signature but not norm.accept"
    );
    assert!(h
        .prepare(&keys, "outside-adopt", "outsider", vec!["DR-0001".into()])
        .is_err());
    assert_eq!(h.capture(), before);
    let mut h = h;
    let request = h
        .prepare(&keys, "explicit", "owner", vec!["DR-0001".into()])
        .expect("explicit current acceptance");
    assert_eq!(request.descriptor.adoptions.len(), 1);
    assert_eq!(
        request.descriptor.adoptions[0].mode,
        "explicit_adoption_now"
    );
    h.import(&request, &keys)
        .expect("authorized explicit adoption");
}
#[test]
fn public_descriptor_edits_and_retirement_cannot_remap_installed_history() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "immutable", "owner", vec![])
        .expect("prepare");
    h.import(&request, &keys).expect("import");
    let (pin, _) = h.capture();
    let mut altered = request.descriptor.clone();
    altered.mapping[0].record = altered.mapping[1].record.clone();
    let edit=keys.event("outsider","public-edit",NormAct::Edit{ledger:pin.ledger.clone(),authority:Some(pin.authority_head.clone()),vocabulary:vocab("assertion"),record:request.descriptor_record.clone(),previous:request.descriptor_active.clone(),fields_json:json!({"title":"changed public draft","statement":altered.canonical_json().expect("json"),"subject":"changed"}).to_string()});
    let edit_id = h
        .append(&edit, &keys)
        .expect("ordinary public editing remains supported");
    assert_eq!(
        h.resolve(&keys, &request.descriptor.mapping[0].number)
            .expect("original map after edit"),
        Some(request.descriptor.mapping[0].record.clone())
    );
    let retire = keys.event(
        "owner",
        "retire",
        NormAct::Retire {
            ledger: pin.ledger,
            authority: Some(pin.authority_head),
            vocabulary: vocab("assertion"),
            record: request.descriptor_record.clone(),
            previous: edit_id,
            revision: request.descriptor_record.clone(),
            activation: request.descriptor_active.clone(),
            status: "retired".into(),
        },
    );
    h.append(&retire, &keys).expect("ordinary retirement");
    assert_eq!(
        h.resolve(&keys, &request.descriptor.mapping[0].number)
            .expect("original map after retirement"),
        Some(request.descriptor.mapping[0].record.clone())
    );
    let before = h.capture();
    let remap = h
        .prepare(&keys, "retired-remap", "owner", vec![])
        .expect("prepare remap");
    assert!(h.import(&remap, &keys).is_err());
    assert_eq!(h.capture(), before);
}
#[test]
fn original_descriptor_substitution_before_activation_refuses_resolution() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "substitution", "owner", vec![])
        .expect("prepare");
    let partial: Vec<_> = request
        .events
        .iter()
        .filter(|e| e.event_id != request.descriptor_active)
        .cloned()
        .collect();
    h.restore(&partial, &keys)
        .expect("ordinary proposed carrier prefix");
    let (pin, _) = h.capture();
    let edit=keys.event("outsider","before-install",NormAct::Edit{ledger:pin.ledger.clone(),authority:Some(pin.authority_head.clone()),vocabulary:vocab("assertion"),record:request.descriptor_record.clone(),previous:request.descriptor_record.clone(),fields_json:json!({"title":"substituted public draft","statement":request.descriptor.canonical_json().expect("descriptor"),"subject":request.descriptor.source.scope}).to_string()});
    let edited = h
        .append(&edit, &keys)
        .expect("public edit before activation");
    let active = keys.event(
        "owner",
        "edited-install",
        NormAct::Transition {
            ledger: pin.ledger,
            authority: Some(pin.authority_head),
            vocabulary: vocab("assertion"),
            record: request.descriptor_record.clone(),
            previous: edited,
            status: "active".into(),
        },
    );
    h.append(&active, &keys)
        .expect("ordinary assertion activation");
    assert!(
        h.resolve(&keys, "DR-0001").is_err(),
        "edited pre-activation revision must not install original map"
    );
}
#[test]
fn late_sql_failure_rolls_back_every_event_alias_checkpoint_and_map() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "rollback", "owner", vec![])
        .expect("prepare");
    let before = h.capture();
    let aliases = h.aliases();
    h.sql(&format!("CREATE TRIGGER fail_governance_activation BEFORE INSERT ON tracker_events WHEN NEW.event_id='{}' BEGIN SELECT RAISE(ABORT,'late governance failure'); END",request.descriptor_active));
    assert!(
        h.import(&request, &keys).is_err(),
        "actual late SQL failure"
    );
    assert_eq!(h.capture(), before);
    assert_eq!(h.aliases(), aliases);
    assert_eq!(h.resolve(&keys, "DR-0001").expect("absent map"), None);
    h.sql("DROP TRIGGER fail_governance_activation");
    h.import(&request, &keys)
        .expect("same original signed batch after restoration");
    assert!(h
        .resolve(&keys, "DR-0001")
        .expect("restored resolution")
        .is_some());
}

use crate::do_store::{test_support::RusqliteDoSql, DoSql, DoSqliteStore};
use whipplescript_store::items::TrackerEvent;
struct Harness {
    store: DoSqliteStore<RusqliteDoSql>,
}
impl Harness {
    fn new() -> Self {
        Self {
            store: crate::do_store::test_support::store(),
        }
    }
    fn append(&mut self, event: &SignedNormEvent, keys: &Keys) -> StoreResult<String> {
        self.store.append_norm_event(event, keys)
    }
    fn capture(&self) -> (NormCheckpoint, Vec<TrackerEvent>) {
        (
            self.store
                .norm_checkpoint()
                .expect("DO pin")
                .expect("pinned genesis"),
            self.store
                .export_events()
                .expect("DO complete history")
                .into_iter()
                .filter(|e| e.kind.starts_with("norm."))
                .collect(),
        )
    }
    fn import(
        &mut self,
        r: &GovernanceImportRequest,
        k: &Keys,
    ) -> StoreResult<GovernanceImportResult> {
        self.store.import_governance(r, k)
    }
    fn restore(&mut self, e: &[TrackerEvent], k: &Keys) -> StoreResult<usize> {
        self.store.import_norm_events(e, k)
    }
    fn sql(&self, s: &str) {
        self.store
            .sql
            .execute(s, &[])
            .expect("owning DO fixture SQL");
    }
    fn aliases(&self) -> String {
        format!(
            "{:?}",
            self.store
                .sql
                .query(
                    "SELECT record_id,ordinal FROM tracker_norm_aliases ORDER BY ordinal",
                    &[]
                )
                .expect("DO aliases")
        )
    }
}

#[test]
fn source_and_wire_parser_refuse_hidden_or_omitted_content() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "parser", "owner", vec![])
        .expect("prepare");
    let before = h.capture();
    for suffix in [
        b" trailing-noncomment".as_slice(),
        b" /* unfinished".as_slice(),
    ] {
        let mut raw = SOURCE.to_vec();
        raw.extend_from_slice(suffix);
        assert!(
            GovernanceSource::from_bytes("scope".into(), "revision".into(), "log".into(), &raw)
                .is_err(),
            "complete source must refuse trailing bytes/comment"
        );
    }
    let duplicate=br#"{"schemaVersion":1,"events":[{"decisionId":"DR-0001","state":"proposed","nested":{"x":1,"x":2}}]}"#;
    assert!(GovernanceSource::from_bytes(
        "scope".into(),
        "revision".into(),
        "log".into(),
        duplicate
    )
    .is_err());
    let mut wrong = request.clone();
    wrong.descriptor.chronology.remove(1);
    assert!(h.import(&wrong, &keys).is_err());
    assert_eq!(h.capture(), before);
    let mut extra = request.clone();
    extra.events.push(
        keys.event(
            "owner",
            "unrelated-roster",
            NormAct::Create {
                ledger: request.descriptor.destination.ledger.clone(),
                authority: Some(request.descriptor.destination.authority.clone()),
                vocabulary: vocab("assertion"),
                fields_json: json!({"title":"unrelated","statement":"not in signed descriptor"})
                    .to_string(),
            },
        )
        .tracker_event()
        .expect("event"),
    );
    assert!(h.import(&extra, &keys).is_err());
    assert_eq!(h.capture(), before);
    let raw = serde_json::to_string(&request).expect("wire");
    let duplicate = raw.replacen(
        "\"protocol\":",
        "\"protocol\":\"duplicate\",\"protocol\":",
        1,
    );
    assert!(decode_request(&duplicate).is_err());
    let mut unknown = serde_json::to_value(&request).expect("wire value");
    unknown["unknown"] = json!(true);
    assert!(decode_request(&unknown.to_string()).is_err());
    let mut wrong = request.clone();
    wrong.descriptor.mapping[0].record = wrong.descriptor.mapping[1].record.clone();
    assert!(h.import(&wrong, &keys).is_err());
    assert_eq!(h.capture(), before);
}
#[test]
fn retained_retry_and_map_survive_real_charter_succession() {
    use whipplescript_store::norm_activation::{MigrationPlan, VocabularyMigration};
    let (mut h, keys) = Harness::seeded();
    let request = h.prepare(&keys, "epoch", "owner", vec![]).expect("prepare");
    h.import(&request, &keys).expect("first import");
    let (pin, history) = h.capture();
    let view = replay_norm(&history, &pin, &keys).expect("actual current projection");
    let old = NormCharter::bundled().expect("old charter");
    let mut successor = old.clone();
    let definition = &mut successor
        .vocabularies
        .iter_mut()
        .find(|v| v.definition.name == "decision")
        .expect("decision")
        .definition;
    definition.version = "2".into();
    let next = whipplescript_core::vocabulary::Vocabulary::new(definition.clone())
        .expect("successor declaration")
        .reference()
        .clone();
    let migration = old
        .vocabularies
        .iter()
        .map(|v| {
            let from = whipplescript_core::vocabulary::Vocabulary::new(v.definition.clone())
                .expect("old declaration")
                .reference()
                .clone();
            let plan = if v.definition.name == "decision" {
                MigrationPlan::Successor {
                    vocabulary: next.clone(),
                    statuses: v
                        .definition
                        .status
                        .values
                        .iter()
                        .map(|s| (s.clone(), s.clone()))
                        .collect(),
                }
            } else {
                MigrationPlan::Retain {}
            };
            VocabularyMigration { from, plan }
        })
        .collect();
    let activation = keys.event(
        "owner",
        "new-charter",
        NormAct::Activate {
            ledger: view.ledger,
            previous: view.authority_head,
            charter: successor,
            migration,
            changes: vec![],
            frontier: view.frontier.into_iter().collect(),
        },
    );
    h.append(&activation, &keys)
        .expect("legitimate ordinary charter succession");
    let before = h.capture();
    assert_ne!(
        before.0.authority_head,
        request.descriptor.destination.authority
    );
    let retry = h
        .import(&request, &keys)
        .expect("historical retry after declaration/authority advance");
    assert!(retry.replayed);
    assert_eq!(retry.admitted, 0);
    assert_eq!(h.capture(), before);
    for m in &request.descriptor.mapping {
        assert_eq!(
            h.resolve(&keys, &m.number)
                .expect("old map under exact historical definition"),
            Some(m.record.clone())
        );
    }
    let old_act = keys.event(
        "owner",
        "old-standing",
        NormAct::Create {
            ledger: request.descriptor.destination.ledger.clone(),
            authority: Some(request.descriptor.destination.authority.clone()),
            vocabulary: vocab("assertion"),
            fields_json: json!({"title":"old standing","statement":"must refuse"}).to_string(),
        },
    );
    assert!(
        h.append(&old_act, &keys).is_err(),
        "historical retry grants no old current standing"
    );
    assert_eq!(h.capture(), before);
}
#[test]
fn complete_hjson_accepts_real_comments_and_refuses_lone_trailing_markers() {
    for suffix in [b" /".as_slice(), b" *".as_slice()] {
        let mut raw = SOURCE.to_vec();
        raw.extend_from_slice(suffix);
        assert!(
            GovernanceSource::from_bytes("scope".into(), "rev".into(), "log".into(), &raw).is_err(),
            "complete source must refuse lone noncomment marker"
        );
    }
    for suffix in [
        b" // real trailing line comment".as_slice(),
        b" /* real trailing block comment */".as_slice(),
    ] {
        let mut raw = SOURCE.to_vec();
        raw.extend_from_slice(suffix);
        let source = GovernanceSource::from_bytes("scope".into(), "rev".into(), "log".into(), &raw)
            .expect("valid real trailing comment");
        assert_eq!(source.event_count, 4);
    }
    let raw = br#"{
 schemaVersion: 1
 events: [
  {
   decisionId: DR-0001
   state: proposed
   title: "Quoted // and /* markers are source content"
   body: '''
     multiline source / and * remain content
     no discarded chronology
     '''
  }
 ]
}"#;
    assert_eq!(
        GovernanceSource::from_bytes("scope".into(), "rev".into(), "log".into(), raw)
            .expect("full HJSON string grammar")
            .event_count,
        1
    );
}
#[test]
fn partial_import_and_ordinary_conflicting_installation_are_not_retry_success() {
    let (mut h, keys) = Harness::seeded();
    let request = h
        .prepare(&keys, "partial", "owner", vec![])
        .expect("prepare");
    h.restore(&[request.events[0].clone()], &keys)
        .expect("ordinary historical partial restoration");
    let before = h.capture();
    assert!(
        h.import(&request, &keys).is_err(),
        "partial admitted roster must not be filled in as fresh success"
    );
    assert_eq!(h.capture(), before);
    let (mut h, keys) = Harness::seeded();
    let first = h.prepare(&keys, "first", "owner", vec![]).expect("prepare");
    h.import(&first, &keys).expect("first");
    let second = h
        .prepare(&keys, "ordinary-second", "owner", vec![])
        .expect("second legitimate signed batch");
    h.restore(&second.events, &keys)
        .expect("ordinary verified norm history transport preserves concurrent data");
    let before = h.capture();
    assert!(
        h.resolve(&keys, "DR-0001").is_err(),
        "historical competing installations cannot choose a favorable map"
    );
    assert!(
        h.import(&first, &keys).is_err(),
        "ambiguous retained mapping cannot report retry success"
    );
    assert_eq!(h.capture(), before);
    let (pin, mut history) = before;
    history.retain(|e| e.event_id != first.descriptor.mapping[0].record);
    assert!(
        resolve_governance_reference(&history, &pin, &keys, "GaugeWright/decisions", "DR-0001")
            .is_err(),
        "missing retained roster evidence refuses read recovery"
    );
}
