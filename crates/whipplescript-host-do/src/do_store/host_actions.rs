//! DO realization of the same atomic instance/command/input admission as native.
use super::*;
use whipplescript_store::host_actions::{HostActionAdmission, HostActionStart};

impl<Sql: DoSql> DoSqliteStore<Sql> {
    pub(super) fn admit_host_action_atomic(
        &mut self,
        action: HostActionStart<'_>,
    ) -> StoreResult<HostActionAdmission> {
        let payload = action.admission_payload()?;
        let mut result = None;
        self.sql.atomic(&mut || {
            let admitted = admit_on(&self.sql, action, &payload)?;
            result = Some(admitted);
            Ok(())
        })?;
        result.ok_or_else(|| StoreError::Conflict("host action transaction did not execute".into()))
    }
}

fn admit_on<Sql: DoSql>(
    sql: &Sql,
    action: HostActionStart<'_>,
    payload: &str,
) -> StoreResult<HostActionAdmission> {
    let existing = sql.query(
        "SELECT event_id, sequence, payload_json FROM events WHERE instance_id = ?1 AND idempotency_key = 'host-action-admission'",
        &[text(action.instance_id)],
    ).map_err(sql_err)?;
    if let Some(row) = existing.first() {
        if as_text(&row[2]) != payload {
            return Err(StoreError::Conflict(
                "host action identity already binds a different command or input".into(),
            ));
        }
        return Ok(HostActionAdmission {
            instance_id: action.instance_id.into(),
            admitted: StoredEvent {
                event_id: as_text(&row[0]),
                sequence: as_i64(&row[1]),
            },
            replayed: true,
        });
    }
    create_instance_on(
        sql,
        action.instance,
        action.authority,
        Some(action.instance_id),
    )?;
    let admitted = do_append_event(
        sql,
        NewEvent {
            instance_id: action.instance_id,
            event_type: "host.action.admitted",
            payload_json: payload,
            source: "host-runtime",
            causation_id: None,
            correlation_id: Some(action.fingerprint),
            idempotency_key: Some("host-action-admission"),
        },
    )?;
    let started = do_append_event(
        sql,
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
        let derived = do_append_event(
            sql,
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
        do_insert_fact(
            sql,
            action.instance_id,
            "host-runtime",
            &derived.event_id,
            Some(action.instance.version_id),
            0,
            fact,
        )?;
    }
    Ok(HostActionAdmission {
        instance_id: action.instance_id.into(),
        admitted,
        replayed: false,
    })
}

pub(super) fn create_instance_on<Sql: DoSql>(
    sql: &Sql,
    instance: NewInstance<'_>,
    authority: NewInstanceAuthority<'_>,
    instance_id: Option<&str>,
) -> StoreResult<InstanceRecord> {
    let rows = sql.query(
                "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
                 effective_authority, status, input_json, started_at) VALUES \
                 (COALESCE(?6, 'ins_' || lower(hex(randomblob(16)))), ?1, ?2, ?3, ?4, 'running', ?5, \
                 CURRENT_TIMESTAMP) RETURNING instance_id, status, program_id, version_id, \
                 revision_epoch, workflow_principal, effective_authority, input_json, \
                 created_at, started_at",
                &[
                    text(instance.program_id),
                    text(instance.version_id),
                    text(authority.workflow_principal),
                    text(authority.effective_authority_json),
                    text(instance.input_json),
                    opt_text(instance_id),
                ],
            )
            .map_err(sql_err)?;
    let row = rows
        .first()
        .ok_or_else(|| sql_err("create_instance returned no row".to_string()))?;
    let record = InstanceRecord {
        instance_id: as_text(&row[0]),
        status: as_text(&row[1]),
    };
    // DR-0094 parity: creation is an event on this host too, so the DO's
    // rebuild folds the same identity the native store's does. Without it
    // the two hosts would disagree about what a rebuilt instance row is.
    let started_at = match &row[9] {
        SqlValue::Null => serde_json::Value::Null,
        other => serde_json::Value::String(as_text(other)),
    };
    let payload = serde_json::json!({
        "program_id": as_text(&row[2]),
        "version_id": as_text(&row[3]),
        "revision_epoch": as_opt_i64(&row[4]).unwrap_or(0),
        "workflow_principal": as_text(&row[5]),
        "effective_authority": as_text(&row[6]),
        "input_json": as_text(&row[7]),
        "created_at": as_text(&row[8]),
        "started_at": started_at,
        "status": record.status,
    })
    .to_string();
    do_append_event(
        sql,
        NewEvent {
            instance_id: &record.instance_id,
            event_type: "instance.created",
            payload_json: &payload,
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        },
    )?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnsupportedSql;
    impl DoSql for UnsupportedSql {
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            panic!("an unsupported atomic bridge must never reach SQL")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            panic!("an unsupported atomic bridge must never reach SQL")
        }
    }

    #[test]
    fn host_action_bridge_without_transactions_refuses_before_the_callback() {
        let mut called = false;
        assert!(UnsupportedSql
            .atomic(&mut || {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
    }

    struct SilentSql;
    impl DoSql for SilentSql {
        fn atomic(&self, _: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            Ok(())
        }
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            panic!("the faulty bridge never invokes the admission")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            panic!("the faulty bridge never invokes the admission")
        }
    }

    #[test]
    fn host_action_bridge_cannot_acknowledge_an_unexecuted_transaction() {
        use whipplescript_store::host_actions::conformance;
        let mut fixture =
            DoSqliteStore::new(super::super::test_support::RusqliteDoSql::with_runtime_schema());
        let version = conformance::register(&mut fixture);
        let mut faulty = DoSqliteStore::new(SilentSql);
        let error = faulty
            .admit_host_action(conformance::action(&version))
            .expect_err("no admission occurred");
        assert!(format!("{error:?}").contains("did not execute"));
    }
}
