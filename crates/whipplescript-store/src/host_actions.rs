//! Atomic host-action admission storage, shared by the native and DO kernels.
//!
//! This is a storage primitive, not an authentication API. The kernel supplies
//! an already verified command and compiler-validated ordinary workflow inputs.

use crate::{NewFact, NewInstance, NewInstanceAuthority, StoredEvent};

pub const HOST_ACTION_INSTANCE_PREFIX: &str = "ins_action_";

/// An indexed, bounded read: a dispatch needs the original admission prefix,
/// not the action's growing execution history. Both SQL hosts use this query.
pub const ACTION_ADMISSION_PREFIX_SQL: &str =
    "SELECT event_id, sequence, event_type, payload_json, occurred_at, source, \
     causation_id, correlation_id, idempotency_key, format_version \
     FROM events WHERE instance_id = ?1 AND sequence <= \
     (SELECT sequence FROM events WHERE instance_id = ?1 \
      AND idempotency_key = 'host-action-admission') ORDER BY sequence ASC";

/// The immutable action origin carried by each external attempt. The frame
/// owns the instance identity; this pin binds its original command and all of
/// that command's authority, provenance, labeled inputs and resource bases.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAdmissionBinding {
    pub fingerprint: String,
    pub sequence: i64,
    pub head_digest: String,
}

pub fn dispatch_admission_binding(
    instance_id: &str,
    prefix: &[crate::event_chain::OwnedChainEntry],
) -> crate::StoreResult<Option<ActionAdmissionBinding>> {
    use crate::StoreError;
    if prefix.is_empty() {
        if instance_id.starts_with(HOST_ACTION_INSTANCE_PREFIX) {
            return Err(StoreError::Conflict(
                "action dispatch has no recorded admission".into(),
            ));
        }
        return Ok(None);
    }
    let admitted = &prefix[prefix.len() - 1];
    let contiguous = prefix.iter().enumerate().all(|(index, event)| {
        i64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            == Some(event.sequence)
    });
    if !contiguous
        || admitted.source.as_deref() != Some("host-runtime")
        || admitted.event_type != "host.action.admitted"
        || admitted.idempotency_key.as_deref() != Some("host-action-admission")
    {
        return Err(StoreError::Conflict(
            "action dispatch admission prefix is invalid".into(),
        ));
    }
    #[derive(serde::Deserialize)]
    struct Admission {
        fingerprint: String,
    }
    let admission: Admission = serde_json::from_str(&admitted.payload_json)?;
    if admission.fingerprint.trim().is_empty() {
        return Err(StoreError::Conflict(
            "action dispatch admission fingerprint is empty".into(),
        ));
    }
    Ok(Some(ActionAdmissionBinding {
        fingerprint: admission.fingerprint,
        sequence: admitted.sequence,
        head_digest: crate::event_chain::fold_owned(instance_id, prefix).digest,
    }))
}

#[cfg(feature = "native")]
pub(crate) fn native_dispatch_admission_binding(
    connection: &rusqlite::Connection,
    instance_id: &str,
) -> crate::StoreResult<Option<ActionAdmissionBinding>> {
    let mut statement = connection.prepare(ACTION_ADMISSION_PREFIX_SQL)?;
    let prefix = statement
        .query_map([instance_id], |row| {
            Ok(crate::event_chain::OwnedChainEntry {
                event_id: row.get(0)?,
                sequence: row.get(1)?,
                event_type: row.get(2)?,
                payload_json: crate::runtime_protection::read_event_payload(
                    connection, row, 0, 2, 3,
                )?,
                occurred_at: row.get(4)?,
                source: row.get(5)?,
                causation_id: row.get(6)?,
                correlation_id: row.get(7)?,
                idempotency_key: row.get(8)?,
                format_version: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    dispatch_admission_binding(instance_id, &prefix)
}

#[cfg(test)]
mod dispatch_binding_tests {
    use super::*;
    use crate::event_chain::OwnedChainEntry;

    fn prefix() -> Vec<OwnedChainEntry> {
        let created = OwnedChainEntry {
            event_id: "created".into(),
            sequence: 1,
            event_type: "instance.created".into(),
            payload_json: "{}".into(),
            occurred_at: "2026-09-05T00:00:00Z".into(),
            source: Some("kernel".into()),
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            format_version: Some(1),
        };
        vec![created.clone(), OwnedChainEntry {
            event_id: "admitted".into(), sequence: 2, event_type: "host.action.admitted".into(),
            payload_json: r#"{"fingerprint":"bound-command","command":{"policy":"original","input":"immutable","basis":"cut:1"}}"#.into(),
            source: Some("host-runtime".into()), idempotency_key: Some("host-action-admission".into()), ..created
        }]
    }

    #[test]
    fn dispatch_binding_retains_the_complete_original_admission() {
        let prefix = prefix();
        let first = dispatch_admission_binding("ins_action_fixture", &prefix)
            .unwrap()
            .unwrap();
        assert_eq!(first.fingerprint, "bound-command");
        assert_eq!(first.sequence, 2);
        assert_eq!(
            first.head_digest,
            crate::event_chain::fold_owned("ins_action_fixture", &prefix).digest
        );
        let mut changed = prefix.clone();
        changed[1].payload_json = changed[1].payload_json.replace("cut:1", "cut:2");
        assert_ne!(
            dispatch_admission_binding("ins_action_fixture", &changed)
                .unwrap()
                .unwrap()
                .head_digest,
            first.head_digest
        );
        assert_ne!(
            dispatch_admission_binding("ins_action_other", &prefix)
                .unwrap()
                .unwrap()
                .head_digest,
            first.head_digest
        );
        assert_eq!(
            dispatch_admission_binding("legacy-instance", &[]).unwrap(),
            None
        );
    }

    #[test]
    fn dispatch_binding_refuses_missing_forged_or_gapped_action_origin() {
        assert!(dispatch_admission_binding("ins_action_fixture", &[]).is_err());
        let prefix = prefix();
        for field in ["source", "type", "key", "gap", "fingerprint"] {
            let mut changed = prefix.clone();
            match field {
                "source" => changed[1].source = Some("external".into()),
                "type" => changed[1].event_type = "external.started".into(),
                "key" => changed[1].idempotency_key = None,
                "gap" => changed[0].sequence = 0,
                "fingerprint" => changed[1].payload_json = r#"{"fingerprint":" "}"#.into(),
                _ => unreachable!(),
            }
            assert!(
                dispatch_admission_binding("ins_action_fixture", &changed).is_err(),
                "{field}"
            );
        }
        assert!(dispatch_admission_binding("ins_action_fixture", &prefix[1..]).is_err());
    }
}

/// The same executable fixture is consumed by native and hosted stores. It
/// tests the storage boundary; compiler/authentication fixtures live in kernel.
pub mod conformance {
    use super::*;
    use crate::{NewProgramVersion, ProgramVersionRecord, RuleCommit, RuntimeStore};

    pub fn register(store: &mut impl RuntimeStore) -> ProgramVersionRecord {
        store
            .create_program_version(NewProgramVersion {
                program_name: "HostActionConformance",
                source_hash: "action-source",
                ir_hash: "action-ir",
                ir_snapshot: None,
                compiler_version: "fixture",
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            })
            .expect("register action fixture")
    }

    pub fn action(version: &ProgramVersionRecord) -> HostActionStart<'_> {
        static FACTS: [NewFact<'static>; 2] = [
            NewFact {
                fact_id: "action-first",
                name: "Input",
                key: "first",
                value_json: r#"{"handle":"input:1"}"#,
                schema_id: None,
                provenance_class: "external",
                correlation_id: Some("action-fingerprint"),
                source_span_json: None,
            },
            NewFact {
                fact_id: "action-second",
                name: "Input",
                key: "second",
                value_json: r#"{"handle":"input:2"}"#,
                schema_id: None,
                provenance_class: "external",
                correlation_id: Some("action-fingerprint"),
                source_span_json: None,
            },
        ];
        HostActionStart {
            instance_id: "ins_action_fixture",
            fingerprint: "action-fingerprint",
            command_json: r#"{"request_id":"request:1","input_ref":"immutable:1"}"#,
            instance: NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: r#"{"first":{"handle":"input:1"},"second":{"handle":"input:2"}}"#,
            },
            authority: NewInstanceAuthority {
                workflow_principal: "workflow:fixture/Action",
                effective_authority_json: r#"["workflow:fixture/Action"]"#,
            },
            input_facts: &FACTS,
        }
    }

    pub fn check<S: RuntimeStore + crate::log_append::LogAppend>(store: &mut S) {
        let version = register(store);
        let action = action(&version);
        let first = store.admit_host_action(action).expect("admit");
        assert!(!first.replayed);
        assert_eq!(first.admitted.sequence, 2);
        let events = store.list_events(action.instance_id).expect("events");
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            [
                "instance.created",
                "host.action.admitted",
                "external.started",
                "fact.derived",
                "fact.derived"
            ]
        );
        assert_eq!(
            store.list_facts(action.instance_id).expect("facts").len(),
            2
        );

        let replay = store.admit_host_action(action).expect("reattach");
        assert!(replay.replayed);
        assert_eq!(replay.admitted, first.admitted);
        assert_eq!(
            store
                .list_events(action.instance_id)
                .expect("action conformance"),
            events
        );
        for altered in [
            HostActionStart {
                fingerprint: "different",
                ..action
            },
            HostActionStart {
                command_json: r#"{"request_id":"request:1","input_ref":"immutable:2"}"#,
                ..action
            },
            HostActionStart {
                instance: NewInstance {
                    input_json: "{}",
                    ..action.instance
                },
                ..action
            },
            HostActionStart {
                authority: NewInstanceAuthority {
                    workflow_principal: "another",
                    ..action.authority
                },
                ..action
            },
            HostActionStart {
                input_facts: &[],
                ..action
            },
        ] {
            assert!(
                store.admit_host_action(altered).is_err(),
                "changed meaning must refuse"
            );
            assert_eq!(
                store
                    .list_events(action.instance_id)
                    .expect("action conformance"),
                events,
                "a refused retry appends nothing"
            );
        }
        store
            .commit_rule(RuleCommit {
                instance_id: action.instance_id,
                rule: "consume",
                trigger_event_id: Some(&first.admitted.event_id),
                facts: &[],
                consumed_fact_ids: &["action-first"],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("consume-once"),
                marks: &[],
                context_json: None,
            })
            .expect("ordinary rule consumes an admitted input");
        let consumed = store
            .list_facts(action.instance_id)
            .expect("action conformance");
        assert_eq!(consumed.len(), 1);
        store
            .admit_host_action(action)
            .expect("retry after execution");
        assert_eq!(
            store
                .list_facts(action.instance_id)
                .expect("action conformance"),
            consumed,
            "retry must not resurrect a consumed input"
        );
        store
            .rebuild_projections(action.instance_id)
            .expect("rebuild");
        assert_eq!(
            store
                .list_facts(action.instance_id)
                .expect("action conformance"),
            consumed
        );
        assert_eq!(
            store
                .admit_host_action(action)
                .expect("action conformance")
                .admitted,
            first.admitted
        );
        let prefix = store
            .chain_prefix(action.instance_id)
            .expect("admission prefix");
        let expected_binding = dispatch_admission_binding(action.instance_id, &prefix[..2])
            .expect("recorded admission")
            .expect("action binding");
        store
            .commit_rule(RuleCommit {
                instance_id: action.instance_id,
                rule: "dispatch",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[crate::NewEffect {
                    effect_id: "action-timer",
                    kind: "timer.wait",
                    target: None,
                    input_json: "{}",
                    status: "queued",
                    idempotency_key: "action-timer",
                    required_capabilities_json: "[]",
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("dispatch-rule"),
                marks: &[],
                context_json: None,
            })
            .expect("ordinary action effect");
        store.start_run(crate::RunStart {
            instance_id: action.instance_id, effect_id: "action-timer", run_id: "action-run",
            provider: "builtin", worker_id: "fixture", lease_id: "action-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: r#"{"action_admission":{"fingerprint":"forged","sequence":99,"head_digest":"forged"}}"#,
        }).expect("dispatch binds storage evidence, not metadata claims");
        let events = store
            .list_events(action.instance_id)
            .expect("dispatch events");
        let attempts =
            crate::effect_recovery::fold_attempts(action.instance_id, "action-timer", &events)
                .expect("attempts");
        assert_eq!(
            attempts[0]
                .dispatch
                .as_ref()
                .expect("dispatch marker")
                .frame
                .action_admission
                .as_ref(),
            Some(&expected_binding)
        );
        store
            .rebuild_projections(action.instance_id)
            .expect("rebuild dispatched action");
        assert_eq!(
            crate::effect_recovery::fold_attempts(
                action.instance_id,
                "action-timer",
                &store
                    .list_events(action.instance_id)
                    .expect("rebuilt events")
            )
            .expect("rebuilt attempts"),
            attempts
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HostActionStart<'a> {
    pub instance_id: &'a str,
    pub fingerprint: &'a str,
    pub command_json: &'a str,
    pub instance: NewInstance<'a>,
    pub authority: NewInstanceAuthority<'a>,
    pub input_facts: &'a [NewFact<'a>],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostActionAdmission {
    pub instance_id: String,
    pub admitted: StoredEvent,
    pub replayed: bool,
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::SqliteStore;

    #[test]
    fn host_action_native_admission_conformance() {
        conformance::check(&mut SqliteStore::open_in_memory().unwrap());
    }

    #[test]
    fn host_action_native_concurrent_delivery_and_restart_keep_one_admission() {
        use std::sync::{Arc, Barrier};
        let path = std::env::temp_dir().join(format!(
            "whip-host-action-race-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut initial = SqliteStore::open(&path).unwrap();
        let version = conformance::register(&mut initial);
        drop(initial);
        let barrier = Arc::new(Barrier::new(4));
        let deliveries: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                let version = version.clone();
                std::thread::spawn(move || {
                    let mut store = SqliteStore::open(path).unwrap();
                    barrier.wait();
                    store
                        .admit_host_action(conformance::action(&version))
                        .unwrap()
                })
            })
            .collect();
        let receipts: Vec<_> = deliveries
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            receipts.iter().filter(|receipt| !receipt.replayed).count(),
            1
        );
        assert!(receipts
            .iter()
            .all(|receipt| receipt.admitted == receipts[0].admitted));
        let mut reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(reopened.list_instances().unwrap().len(), 1);
        let events = reopened.list_events("ins_action_fixture").unwrap();
        assert_eq!(events.len(), 5);
        let retry = reopened
            .admit_host_action(conformance::action(&version))
            .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.admitted, receipts[0].admitted);
        assert_eq!(reopened.list_events("ins_action_fixture").unwrap(), events);
        assert_eq!(reopened.list_facts("ins_action_fixture").unwrap().len(), 2);
    }

    #[test]
    fn host_action_native_rolls_back_at_each_admission_boundary() {
        for (table, predicate) in [
            ("instances", "1"),
            ("events", "NEW.event_type = 'instance.created'"),
            ("events", "NEW.event_type = 'host.action.admitted'"),
            ("events", "NEW.event_type = 'external.started'"),
            ("events", "NEW.event_type = 'fact.derived' AND json_extract(NEW.payload_json, '$.key') = 'first'"),
            ("facts", "NEW.key = 'first'"),
            ("events", "NEW.event_type = 'fact.derived' AND json_extract(NEW.payload_json, '$.key') = 'second'"),
            ("facts", "NEW.key = 'second'"),
        ] {
            let mut store = SqliteStore::open_in_memory().unwrap();
            let version = conformance::register(&mut store);
            let action = conformance::action(&version);
            store.connection.execute_batch(&format!(
                "CREATE TRIGGER action_failure BEFORE INSERT ON {table} WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'injected admission fault'); END"
            )).unwrap();
            assert!(store.admit_host_action(action).is_err(), "fault at {table}: {predicate}");
            assert!(store.list_instances().unwrap().is_empty());
            assert!(store.list_events(action.instance_id).unwrap().is_empty());
            assert!(store.list_facts(action.instance_id).unwrap().is_empty());
            store.connection.execute_batch("DROP TRIGGER action_failure").unwrap();
            assert!(!store.admit_host_action(action).unwrap().replayed);
            assert_eq!(store.list_facts(action.instance_id).unwrap().len(), 2);
        }
    }
}

impl HostActionStart<'_> {
    /// This payload is compared on re-delivery. In addition to the signed
    /// command, it binds the registered program and the validated input facts;
    /// a faulty host cannot quietly re-resolve an immutable input differently.
    pub fn admission_payload(&self) -> crate::StoreResult<String> {
        Ok(serde_json::json!({
            "fingerprint": self.fingerprint,
            "command": serde_json::from_str::<serde_json::Value>(self.command_json)?,
            "program_id": self.instance.program_id,
            "version_id": self.instance.version_id,
            "input": serde_json::from_str::<serde_json::Value>(self.instance.input_json)?,
            "workflow_principal": self.authority.workflow_principal,
            "effective_authority": serde_json::from_str::<serde_json::Value>(self.authority.effective_authority_json)?,
            "input_facts": self.input_facts.iter().map(|fact| {
                Ok(serde_json::json!({
                    "fact_id": fact.fact_id,
                    "name": fact.name,
                    "key": fact.key,
                    "value": serde_json::from_str::<serde_json::Value>(fact.value_json)?,
                    "schema_id": fact.schema_id,
                    "provenance_class": fact.provenance_class,
                    "correlation_id": fact.correlation_id,
                    "source_span_json": fact.source_span_json,
                }))
            }).collect::<crate::StoreResult<Vec<_>>>()?,
        }).to_string())
    }
}

#[cfg(feature = "native")]
impl crate::SqliteStore {
    pub fn admit_host_action(
        &mut self,
        action: HostActionStart<'_>,
    ) -> crate::StoreResult<HostActionAdmission> {
        self.retained_publication()
            .run(|| self.admit_host_action_retained(action))
    }

    fn admit_host_action_retained(
        &mut self,
        action: HostActionStart<'_>,
    ) -> crate::StoreResult<HostActionAdmission> {
        use crate::{append_event_on, insert_fact, NewEvent, StoreError};
        use rusqlite::OptionalExtension;

        let payload = action.admission_payload()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing = tx.query_row(
            "SELECT event_id, sequence, whip_runtime_event_open(event_id, event_type, payload_json) FROM events WHERE instance_id = ?1 AND idempotency_key = 'host-action-admission'",
            [action.instance_id],
            |row| Ok((StoredEvent { event_id: row.get(0)?, sequence: row.get(1)? }, row.get::<_, String>(2)?)),
        ).optional()?;
        if let Some((admitted, recorded)) = existing {
            if recorded != payload {
                return Err(StoreError::Conflict(
                    "host action identity already binds a different command or input".into(),
                ));
            }
            return Ok(HostActionAdmission {
                instance_id: action.instance_id.into(),
                admitted,
                replayed: true,
            });
        }
        // A colliding legacy/incomplete instance must never be adopted as an
        // authenticated action. The primary key refuses its INSERT atomically.
        create_instance_on(
            &tx,
            action.instance,
            action.authority,
            Some(action.instance_id),
        )?;
        let admitted = append_event_on(
            &tx,
            NewEvent {
                instance_id: action.instance_id,
                event_type: "host.action.admitted",
                payload_json: &payload,
                source: "host-runtime",
                causation_id: None,
                correlation_id: Some(action.fingerprint),
                idempotency_key: Some("host-action-admission"),
            },
        )?;
        let started = append_event_on(
            &tx,
            NewEvent {
                instance_id: action.instance_id,
                event_type: "external.started",
                payload_json: action.instance.input_json,
                source: "host-runtime",
                causation_id: Some(&admitted.event_id),
                correlation_id: Some(action.fingerprint),
                idempotency_key: Some("host-action-start"),
            },
        )?;
        for fact in action.input_facts {
            let payload = serde_json::json!({
                "fact_id": fact.fact_id, "name": fact.name, "key": fact.key,
                "value": serde_json::from_str::<serde_json::Value>(fact.value_json)?,
                "schema_id": fact.schema_id, "provenance_class": fact.provenance_class,
                "correlation_id": fact.correlation_id,
            })
            .to_string();
            let derived = append_event_on(
                &tx,
                NewEvent {
                    instance_id: action.instance_id,
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: "host-runtime",
                    causation_id: Some(&started.event_id),
                    correlation_id: Some(action.fingerprint),
                    idempotency_key: Some(fact.fact_id),
                },
            )?;
            insert_fact(
                &tx,
                action.instance_id,
                "host-runtime",
                &derived.event_id,
                Some(action.instance.version_id),
                0,
                fact,
            )?;
        }
        tx.commit()?;
        Ok(HostActionAdmission {
            instance_id: action.instance_id.into(),
            admitted,
            replayed: false,
        })
    }
}

#[cfg(feature = "native")]
pub(super) fn create_instance_on(
    connection: &rusqlite::Connection,
    instance: NewInstance<'_>,
    authority: NewInstanceAuthority<'_>,
    instance_id: Option<&str>,
) -> crate::StoreResult<crate::InstanceRecord> {
    use crate::{append_event_on, CreatedInstance, InstanceRecord, NewEvent};
    use rusqlite::params;
    let (record, created) = connection.query_row(
        r#"
                WITH payload_identity(id) AS MATERIALIZED (SELECT COALESCE(?6, 'ins_' || lower(hex(randomblob(16)))))
                INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, effective_authority, status, input_json, started_at)
                VALUES (
                    (SELECT id FROM payload_identity),
                    ?1,
                    ?2,
                    ?3,
                    ?4,
                    'running',
                    whip_payload_seal('runtime.instances.input_json', (SELECT id FROM payload_identity), ?5),
                    CURRENT_TIMESTAMP
                )
                RETURNING
                    instance_id,
                    status,
                    program_id,
                    version_id,
                    revision_epoch,
                    workflow_principal,
                    effective_authority,
                    whip_payload_open('runtime.instances.input_json', instances.instance_id, input_json),
                    created_at,
                    started_at
                "#,
        params![
            instance.program_id,
            instance.version_id,
            authority.workflow_principal,
            authority.effective_authority_json,
            instance.input_json,
            instance_id,
        ],
        |row| {
            Ok((
                InstanceRecord {
                    instance_id: row.get(0)?,
                    status: row.get(1)?,
                },
                // The timestamps are read back rather than recomputed: the
                // fold has to reproduce what the INSERT actually wrote, and
                // a second `CURRENT_TIMESTAMP` is a different instant.
                CreatedInstance {
                    program_id: row.get::<_, String>(2)?,
                    version_id: row.get::<_, String>(3)?,
                    revision_epoch: row.get::<_, i64>(4)?,
                    workflow_principal: row.get::<_, String>(5)?,
                    effective_authority: row.get::<_, String>(6)?,
                    input_json: row.get::<_, String>(7)?,
                    created_at: row.get::<_, String>(8)?,
                    started_at: row.get::<_, Option<String>>(9)?,
                    status: row.get::<_, String>(1)?,
                },
            ))
        },
    )?;
    append_event_on(
        connection,
        NewEvent {
            instance_id: &record.instance_id,
            event_type: "instance.created",
            payload_json: &created.to_payload(),
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        },
    )?;
    Ok(record)
}
