//! Native Docker ownership custody. Allocation permits only inert creation;
//! neither allocation nor binding authorizes startup, execution, or proof.
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const OWNER_EVENT: &str = "exec.native.owner.allocated";
pub const CONTAINER_EVENT: &str = "exec.native.container.bound";
pub const PROTOCOL: &str = "whipplescript.exec.native-owner/v1";

#[derive(Clone, Copy)]
pub struct Allocation<'a> {
    pub instance_id: &'a str,
    pub run_id: &'a str,
    pub daemon_id: &'a str,
    pub image_id: &'a str,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub tracking_event_id: String,
    pub daemon_id: String,
    pub image_id: String,
    pub owner_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub protocol: String,
    pub owner_event_id: String,
    pub owner: Owner,
    pub container_id: String,
}
pub struct AllocationReceipt {
    pub event: crate::StoredEvent,
    pub owner: Owner,
    /// Only the caller that committed allocation may initiate inert creation.
    pub created: bool,
}
fn key(kind: &str, run: &str) -> String {
    json!([kind, run]).to_string()
}
fn digest_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Allocation<'_> {
    fn owner(&self, tracking: crate::exec_lifetime::Journal<'_>) -> StoreResult<Owner> {
        if self.daemon_id.is_empty()
            || self.daemon_id.len() > 128
            || self.daemon_id.chars().any(char::is_control)
            || !self.image_id.strip_prefix("sha256:").is_some_and(digest_id)
        {
            return Err(StoreError::Conflict(
                "native executor needs a daemon identity and immutable image ID".into(),
            ));
        }
        // Reuse the original tracking validator without writing fence intent.
        let fence = crate::exec_lifetime::Fence {
            instance_id: self.instance_id,
            run_id: self.run_id,
            reason: crate::exec_lifetime::FenceReason::Recovery,
        };
        let verified: crate::exec_lifetime::FenceRecord = serde_json::from_str(&fence.payload(
            tracking.event_id,
            tracking.kind,
            tracking.source,
            tracking.payload,
        )?)?;
        let tracked: serde_json::Value = serde_json::from_str(tracking.payload)?;
        if tracked["executor_url"] != "whip-executor://native/exec" {
            return Err(StoreError::Conflict(
                "native executor owner cannot adopt another transport".into(),
            ));
        }
        let identity = json!([
            PROTOCOL,
            self.instance_id,
            self.run_id,
            tracking.event_id,
            self.daemon_id,
            self.image_id
        ])
        .to_string();
        Ok(Owner {
            protocol: PROTOCOL.into(),
            instance_id: self.instance_id.into(),
            effect_id: verified.effect_id,
            run_id: self.run_id.into(),
            tracking_event_id: tracking.event_id.into(),
            daemon_id: self.daemon_id.into(),
            image_id: self.image_id.into(),
            owner_id: format!("whip-exec-{}", crate::items::sha256_hex(&identity)),
        })
    }
}

#[cfg(feature = "native")]
mod native {
    use super::*;
    use crate::{exec_lifetime::Journal, NewEvent, SqliteStore, StoredEvent};
    use rusqlite::{params, Connection, OptionalExtension};
    type Row = (StoredEvent, String, String, String);
    fn read(connection: &Connection, instance: &str, slot: &str) -> StoreResult<Option<Row>> {
        let row = connection.query_row("SELECT event_id,sequence,event_type,source,payload_json FROM events WHERE instance_id=?1 AND idempotency_key=?2",params![instance,slot],|row| Ok((StoredEvent {event_id:row.get(0)?,sequence:row.get(1)?},row.get(2)?,row.get(3)?,row.get(4)?))).optional()?;
        if row.is_none() {
            let parts: Vec<String> = serde_json::from_str(slot)?;
            if parts.len() == 2 && connection.query_row("SELECT 1 FROM events WHERE instance_id=?1 AND event_type=?2 AND (json_extract(payload_json,'$.run_id')=?3 OR json_extract(payload_json,'$.owner.run_id')=?3) LIMIT 1",params![instance,parts[0],parts[1]],|_| Ok(())).optional()?.is_some() {
                return Err(StoreError::Conflict("native executor journal slot changed".into()));
            }
        }
        Ok(row)
    }
    fn journal(row: &Row) -> Journal<'_> {
        Journal {
            event_id: &row.0.event_id,
            kind: &row.1,
            source: &row.2,
            payload: &row.3,
        }
    }
    fn tracking(connection: &Connection, request: Allocation<'_>) -> StoreResult<Row> {
        read(
            connection,
            request.instance_id,
            &key(crate::exec_lifetime::EVENT_TYPE, request.run_id),
        )?
        .ok_or_else(|| {
            StoreError::Conflict("native executor requires original request custody".into())
        })
    }
    fn verify<T: Serialize>(row: &Row, kind: &str, value: &T) -> StoreResult<()> {
        if row.0.event_id.is_empty()
            || row.1 != kind
            || row.2 != "kernel"
            || serde_json::from_str::<serde_json::Value>(&row.3)? != serde_json::to_value(value)?
        {
            return Err(StoreError::Conflict(
                "native executor ownership record cannot be replaced".into(),
            ));
        }
        Ok(())
    }
    fn owner(
        connection: &Connection,
        instance: &str,
        run: &str,
    ) -> StoreResult<Option<(StoredEvent, Owner)>> {
        let Some(row) = read(connection, instance, &key(OWNER_EVENT, run))? else {
            if read(connection, instance, &key(CONTAINER_EVENT, run))?.is_some() {
                return Err(StoreError::Conflict(
                    "native container allocation is missing".into(),
                ));
            }
            return Ok(None);
        };
        let held: Owner = serde_json::from_str(&row.3)?;
        let request = Allocation {
            instance_id: instance,
            run_id: run,
            daemon_id: &held.daemon_id,
            image_id: &held.image_id,
        };
        let track = tracking(connection, request)?;
        let expected = request.owner(journal(&track))?;
        verify(&row, OWNER_EVENT, &expected)?;
        Ok(Some((row.0, expected)))
    }
    impl SqliteStore {
        pub fn allocate_native_executor(
            &mut self,
            request: Allocation<'_>,
        ) -> StoreResult<AllocationReceipt> {
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let track = tracking(&tx, request)?;
            let expected = request.owner(journal(&track))?;
            if let Some((event, held)) = owner(&tx, request.instance_id, request.run_id)? {
                if held != expected {
                    return Err(StoreError::Conflict(
                        "native executor daemon or image changed".into(),
                    ));
                }
                tx.commit()?;
                return Ok(AllocationReceipt {
                    event,
                    owner: held,
                    created: false,
                });
            }
            if read(
                &tx,
                request.instance_id,
                &key(crate::exec_lifetime::FENCE_EVENT, request.run_id),
            )?
            .is_some()
            {
                return Err(StoreError::Conflict(
                    "fenced executor cannot allocate a new native owner".into(),
                ));
            }
            let running = tx.query_row("SELECT r.metadata_json,e.input_json FROM runs r JOIN effects e ON e.instance_id=r.instance_id AND e.effect_id=r.effect_id WHERE r.instance_id=?1 AND r.run_id=?2 AND r.effect_id=?3 AND r.provider='exec' AND r.worker_id='whip-exec' AND r.status='running' AND e.kind='exec.command' AND e.status='running'",params![request.instance_id,request.run_id,expected.effect_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).optional()?
                .ok_or_else(|| StoreError::Conflict("native executor allocation requires its running invocation".into()))?;
            let original: serde_json::Value = serde_json::from_str(&track.3)?;
            let events = {
                let mut statement = tx.prepare("SELECT event_id,sequence,event_type,payload_json,source,occurred_at FROM events WHERE instance_id=?1 ORDER BY sequence")?;
                let rows = statement
                    .query_map([request.instance_id], |row| {
                        Ok(crate::EventView {
                            event_id: row.get(0)?,
                            sequence: row.get(1)?,
                            event_type: row.get(2)?,
                            payload_json: row.get(3)?,
                            source: row.get(4)?,
                            occurred_at: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            let original_attempt: Option<String> = serde_json::from_value(
                original["invocation"]["invocation"]["attempt_admission_event_id"].clone(),
            )?;
            if crate::attempt_admission::select(&events, &expected.effect_id)? != original_attempt {
                return Err(StoreError::Conflict(
                    "native executor attempt admission changed".into(),
                ));
            }

            crate::exec_lifetime::Track {
                instance_id: request.instance_id,
                effect_id: &expected.effect_id,
                run_id: request.run_id,
                input_json: &original["input"].to_string(),
                invocation_json: &original["invocation"].to_string(),
                executor_url: "whip-executor://native/exec",
            }
            .verify_binding(&running.1, &running.0)?;
            let event = crate::append_event_on(
                &tx,
                NewEvent {
                    instance_id: request.instance_id,
                    event_type: OWNER_EVENT,
                    payload_json: &serde_json::to_string(&expected)?,
                    source: "kernel",
                    causation_id: Some(request.run_id),
                    correlation_id: None,
                    idempotency_key: Some(&key(OWNER_EVENT, request.run_id)),
                },
            )?;
            tx.commit()?;
            Ok(AllocationReceipt {
                event,
                owner: expected,
                created: true,
            })
        }
        pub fn native_executor_owner(
            &self,
            instance: &str,
            run: &str,
        ) -> StoreResult<Option<(StoredEvent, Owner)>> {
            owner(&self.connection, instance, run)
        }
        /// Retain an inert container returned by Docker, including after a fence
        /// raced creation. This is cleanup custody, never permission to start it.
        pub fn bind_native_executor_container(
            &mut self,
            instance: &str,
            run: &str,
            container_id: &str,
        ) -> StoreResult<StoredEvent> {
            if !digest_id(container_id) {
                return Err(StoreError::Conflict(
                    "native executor requires an immutable container ID".into(),
                ));
            }
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (event, held) = owner(&tx, instance, run)?
                .ok_or_else(|| StoreError::Conflict("native executor owner is missing".into()))?;
            let bound = Container {
                protocol: PROTOCOL.into(),
                owner_event_id: event.event_id,
                owner: held,
                container_id: container_id.into(),
            };
            if let Some(row) = read(&tx, instance, &key(CONTAINER_EVENT, run))? {
                verify(&row, CONTAINER_EVENT, &bound)?;
                tx.commit()?;
                return Ok(row.0);
            }
            let reused = tx.query_row("SELECT 1 FROM events WHERE event_type=?1 AND json_extract(payload_json,'$.owner.daemon_id')=?2 AND json_extract(payload_json,'$.container_id')=?3 LIMIT 1",params![CONTAINER_EVENT,bound.owner.daemon_id,container_id],|_| Ok(())).optional()?.is_some();
            if reused {
                return Err(StoreError::Conflict(
                    "native container already belongs to an owner".into(),
                ));
            }
            let event = crate::append_event_on(
                &tx,
                NewEvent {
                    instance_id: instance,
                    event_type: CONTAINER_EVENT,
                    payload_json: &serde_json::to_string(&bound)?,
                    source: "kernel",
                    causation_id: Some(&bound.owner_event_id),
                    correlation_id: None,
                    idempotency_key: Some(&key(CONTAINER_EVENT, run)),
                },
            )?;
            tx.commit()?;
            Ok(event)
        }
        pub fn native_executor_container(
            &self,
            instance: &str,
            run: &str,
        ) -> StoreResult<Option<Container>> {
            let Some(row) = read(&self.connection, instance, &key(CONTAINER_EVENT, run))? else {
                return Ok(None);
            };
            let bound: Container = serde_json::from_str(&row.3)?;
            let (event, held) = owner(&self.connection, instance, run)?
                .ok_or_else(|| StoreError::Conflict("native container owner is missing".into()))?;
            let expected = Container {
                protocol: PROTOCOL.into(),
                owner_event_id: event.event_id,
                owner: held,
                container_id: bound.container_id,
            };
            if !digest_id(&expected.container_id) {
                return Err(StoreError::Conflict(
                    "native container identity is invalid".into(),
                ));
            }
            verify(&row, CONTAINER_EVENT, &expected)?;
            Ok(Some(expected))
        }
    }
}
