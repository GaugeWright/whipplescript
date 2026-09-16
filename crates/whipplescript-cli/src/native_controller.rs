//! Native controller authority, stored on a Docker-owned persistent volume.
//! Workflow snapshots contain references to this authority, never its mutable tip.
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use whipplescript_kernel::{
    exec_barrier, exec_controller,
    exec_invocation::{self, Envelope, Invocation},
    exec_placement,
};
use whipplescript_store::{exec_native_owner::Owner, StoreError, StoreResult};

pub(crate) const PROTOCOL: &str = "whipplescript.exec.native-controller/v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub selected: Invocation,
    pub envelope: Envelope,
}
impl Identity {
    pub fn controller_id(&self) -> String {
        format!("whip-controller-{}", self.selected.run_id())
    }
    fn validate(&self) -> StoreResult<()> {
        self.envelope
            .dispatch(&self.selected)
            .map_err(StoreError::Conflict)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    protocol: String,
    pub identity: Identity,
    pub owner: Option<Owner>,
    pub container_id: Option<String>,
    receipt: Value,
    pub placement: Value,
    controller: Option<Value>,
    pub barrier: Option<Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Read,
    Claim {
        owner: Owner,
    },
    Bind {
        owner: Owner,
        container_id: String,
    },
    Fence {
        fence_id: String,
    },
    /// Trusted adapter only, after deleting the bound immutable container.
    Finish {
        container_id: String,
        barrier_id: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    /// Only the transaction that first retained the owner may create it.
    pub create: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Value>,
    pub state: State,
    pub response: Value,
}
fn decoded(result: Result<String, String>) -> StoreResult<Value> {
    Ok(serde_json::from_str(
        &result.map_err(StoreError::Conflict)?,
    )?)
}
fn encoded(value: &Option<Value>) -> Option<String> {
    value.as_ref().map(Value::to_string)
}
fn digest(text: &str) -> String {
    whipplescript_store::items::sha256_hex(text)
}
impl State {
    fn new(identity: &Identity) -> StoreResult<Self> {
        identity.validate()?;
        let selected = serde_json::to_string(&identity.selected)?;
        let envelope = serde_json::to_string(&identity.envelope)?;
        let receipt = decoded(exec_invocation::claim_json(&selected, &envelope, None))?["decision"]
            ["receipt"]
            .clone();
        let placement = decoded(exec_placement::bind_controller_json(
            &selected,
            &envelope,
            &receipt.to_string(),
            None,
            &identity.controller_id(),
            &identity.selected.run_id(),
        ))?;
        Ok(Self {
            protocol: PROTOCOL.into(),
            identity: identity.clone(),
            owner: None,
            container_id: None,
            receipt,
            placement,
            controller: None,
            barrier: None,
        })
    }
    fn check_owner(&self, owner: &Owner) -> StoreResult<()> {
        if owner.protocol != whipplescript_store::exec_native_owner::PROTOCOL
            || owner.instance_id != self.identity.selected.instance_id
            || owner.effect_id != self.identity.selected.effect_id
            || owner.run_id != self.identity.selected.run_id()
            || owner.owner_id.is_empty()
            || owner.tracking_event_id.is_empty()
        {
            return Err(StoreError::Conflict(
                "native controller owner differs from its invocation".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn validate(&self, identity: &Identity) -> StoreResult<()> {
        identity.validate()?;
        if self.protocol != PROTOCOL || self.identity != *identity {
            return Err(StoreError::Conflict(
                "native controller authority cannot be replaced".into(),
            ));
        }
        if let Some(owner) = &self.owner {
            self.check_owner(owner)?;
        }
        if self.container_id.is_some() && self.owner.is_none() {
            return Err(StoreError::Conflict(
                "native controller lost its physical owner".into(),
            ));
        }
        if self.placement["container_id"] != identity.controller_id()
            || self.placement["dispatch_id"] != identity.selected.run_id()
        {
            return Err(StoreError::Conflict(
                "native controller placement changed".into(),
            ));
        }
        exec_placement::controller_target_json(
            &serde_json::to_string(&identity.selected)?,
            &serde_json::to_string(&identity.envelope)?,
            &self.receipt.to_string(),
            &self.placement.to_string(),
        )
        .map_err(StoreError::Conflict)?;
        exec_barrier::inspect_json(&identity.controller_id(), encoded(&self.barrier).as_deref())
            .map_err(StoreError::Conflict)?;
        let action = self.read()?;
        if action["action"] == "replay" {
            let status = action["status"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| {
                    StoreError::Conflict("native completion status is invalid".into())
                })?;
            let completed = decoded(exec_invocation::complete_json(
                &serde_json::to_string(&identity.selected)?,
                &serde_json::to_string(&identity.envelope)?,
                &self.receipt.to_string(),
                status,
                &action["body"].to_string(),
            ))?;
            if completed != self.receipt {
                return Err(StoreError::Conflict(
                    "native completion lost its receipt".into(),
                ));
            }
        } else if self.receipt["state"] == "completed" {
            return Err(StoreError::Conflict(
                "native receipt lost its controller completion".into(),
            ));
        }
        Ok(())
    }
    fn transition(&mut self, operation: Value) -> StoreResult<Value> {
        let owner = self.identity.controller_id();
        let gate = decoded(exec_barrier::inspect_json(
            &owner,
            encoded(&self.barrier).as_deref(),
        ))?;
        let result = decoded(exec_controller::transition_with_gate_json(
            &owner,
            &self.placement.to_string(),
            encoded(&self.controller).as_deref(),
            &operation.to_string(),
            encoded(&self.barrier).as_deref(),
            gate["generation"].as_str().ok_or_else(|| {
                StoreError::Conflict("native controller generation is missing".into())
            })?,
        ))?;
        self.controller = (!result["record"].is_null()).then(|| result["record"].clone());
        Ok(result["action"].clone())
    }
    fn read(&self) -> StoreResult<Value> {
        let mut copy = self.clone();
        copy.transition(json!({"op":"read"}))
    }
    fn inventory(&self) -> String {
        json!(self.controller.iter().collect::<Vec<_>>()).to_string()
    }
    fn update_barrier(&mut self, result: Value) -> StoreResult<()> {
        let updates = result["updates"]
            .as_array()
            .ok_or_else(|| StoreError::Conflict("native barrier updates are missing".into()))?;
        if updates.len() > 1 {
            return Err(StoreError::Conflict(
                "native controller owns one physical invocation".into(),
            ));
        }
        for update in updates {
            if update["record"]["placement"] != self.placement {
                return Err(StoreError::Conflict(
                    "native barrier changed its invocation".into(),
                ));
            }
            self.controller = Some(update["record"].clone());
        }
        self.barrier = (!result["barrier"].is_null()).then(|| result["barrier"].clone());
        Ok(())
    }
    pub(crate) fn apply(&mut self, command: Command) -> StoreResult<bool> {
        match command {
            Command::Read => {}
            Command::Claim { owner } => {
                self.check_owner(&owner)?;
                if let Some(original) = &self.owner {
                    if original != &owner {
                        return Err(StoreError::Conflict(
                            "native controller physical owner cannot be replaced".into(),
                        ));
                    }
                } else if self.controller.is_none() {
                    self.owner = Some(owner);
                    return Ok(true);
                }
            }
            Command::Bind {
                owner,
                container_id,
            } => {
                self.check_owner(&owner)?;
                if self.owner.as_ref() != Some(&owner)
                    || container_id.len() != 64
                    || !container_id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || self
                        .container_id
                        .as_ref()
                        .is_some_and(|id| id != &container_id)
                {
                    return Err(StoreError::Conflict(
                        "native controller container binding changed".into(),
                    ));
                }
                self.container_id = Some(container_id);
            }
            Command::Fence { fence_id } => {
                self.transition(json!({"op":"ensure_fence","fence_id":fence_id}))?;
                let result = decoded(exec_barrier::begin_json(
                    &self.identity.controller_id(),
                    encoded(&self.barrier).as_deref(),
                    &self.inventory(),
                ))?;
                self.update_barrier(result)?;
            }
            Command::Finish {
                container_id,
                barrier_id,
            } => {
                if self.container_id.as_ref() != Some(&container_id) {
                    return Err(StoreError::Conflict(
                        "native barrier completion targeted another container".into(),
                    ));
                }
                let barrier = encoded(&self.barrier)
                    .ok_or_else(|| StoreError::Conflict("native barrier was not begun".into()))?;
                let result = decoded(exec_barrier::finish_json(
                    &self.identity.controller_id(),
                    &barrier,
                    &self.inventory(),
                    &barrier_id,
                ))?;
                self.update_barrier(result)?;
            }
        }
        Ok(false)
    }
    /// Project already-retained native authority through the shared broker
    /// response codec. No new receipt, placement or execution grant is minted.
    pub(crate) fn resolution_view(&self) -> StoreResult<Value> {
        self.validate(&self.identity)?;
        let projected = decoded(whipplescript_kernel::exec_resolution::transition_json(
            &serde_json::to_string(&self.identity.selected)?,
            &serde_json::to_string(&self.identity.envelope)?,
            &self.receipt.to_string(),
            &self.placement.to_string(),
            None,
            &json!({"op":"observe", "response":self.reply(false)?.response}).to_string(),
        ))?;
        Ok(projected["view"].clone())
    }

    pub(crate) fn reply(&self, create: bool) -> StoreResult<Reply> {
        Ok(Reply {
            create,
            decision: None,
            state: self.clone(),
            response: json!({"protocol":"whipplescript.exec.controller.response/v1", "placement":self.placement, "action":self.read()?}),
        })
    }
}

/// This file belongs to the native runtime authority, never a workflow snapshot.
pub struct Authority {
    connection: Connection,
    lock_path: PathBuf,
}
impl Authority {
    pub fn open(path: &Path) -> StoreResult<Self> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(10))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !matches!(version, 0 | 1) {
            return Err(StoreError::Conflict(
                "native controller schema is unsupported".into(),
            ));
        }
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        if version == 0 {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if current == 0 {
                tx.execute_batch("CREATE TABLE native_controller_tip (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL, digest TEXT NOT NULL); CREATE TABLE native_controller_events (sequence INTEGER PRIMARY KEY, state_json TEXT NOT NULL, digest TEXT NOT NULL); PRAGMA user_version=1;")?;
            } else if current != 1 {
                return Err(StoreError::Conflict(
                    "native controller schema changed during initialization".into(),
                ));
            }
            tx.commit()?;
        }
        Ok(Self {
            connection,
            lock_path: path.with_extension("lock"),
        })
    }
    fn lock(&self) -> StoreResult<File> {
        let file = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)?;
        file.lock()?;
        Ok(file)
    }
    fn transact(
        &mut self,
        identity: &Identity,
        change: impl FnOnce(&mut State) -> StoreResult<(bool, Option<Value>)>,
    ) -> StoreResult<Reply> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let tip: Option<(i64, String)> = tx
            .query_row(
                "SELECT sequence,digest FROM native_controller_tip WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let rows = {
            let mut query = tx.prepare(
                "SELECT sequence,state_json,digest FROM native_controller_events ORDER BY sequence",
            )?;
            let rows = query
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut last = None;
        let mut sequence = 0;
        let mut previous = digest(PROTOCOL);
        for (n, payload, hash) in rows {
            if n != sequence + 1
                || hash != digest(&json!([PROTOCOL, previous, n, payload]).to_string())
            {
                return Err(StoreError::Conflict(
                    "native controller history does not verify".into(),
                ));
            }
            let state: State = serde_json::from_str(&payload)?;
            state.validate(identity)?;
            sequence = n;
            previous = hash;
            last = Some(state);
        }
        if tip != (sequence > 0).then(|| (sequence, previous.clone())) {
            return Err(StoreError::Conflict(
                "native controller authority tip is missing or changed".into(),
            ));
        }
        let mut state = match &last {
            Some(state) => state.clone(),
            None => State::new(identity)?,
        };
        let (create, decision) = change(&mut state)?;
        state.validate(identity)?;
        if last.as_ref() != Some(&state) {
            let n = sequence.checked_add(1).ok_or_else(|| {
                StoreError::Conflict("native controller revision exhausted".into())
            })?;
            let payload = serde_json::to_string(&state)?;
            let hash = digest(&json!([PROTOCOL, previous, n, payload]).to_string());
            let inserted: i64 = tx.query_row("INSERT INTO native_controller_events(sequence,state_json,digest) VALUES (?1,?2,?3) RETURNING sequence", params![n,payload,hash], |r| r.get(0))?;
            let advanced: i64 = tx.query_row("INSERT INTO native_controller_tip(singleton,sequence,digest) VALUES (1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest RETURNING sequence", params![n,hash], |r| r.get(0))?;
            if inserted != n || advanced != n {
                return Err(StoreError::Conflict(
                    "native controller write was not acknowledged".into(),
                ));
            }
        }
        let mut reply = state.reply(create)?;
        reply.decision = decision;
        tx.commit()?;
        Ok(reply)
    }
    pub fn apply(&mut self, identity: &Identity, command: Command) -> StoreResult<Reply> {
        // A finish waits for receiver-owned completion custody. Other commands
        // may close admission while an execution still owns this lock.
        let _lock = matches!(command, Command::Finish { .. })
            .then(|| self.lock())
            .transpose()?;
        self.transact(identity, |state| {
            state.apply(command).map(|create| (create, None))
        })
    }
    /// The receiver retains admission and completion while holding one owner
    /// lock. Host/client death cannot erase a result retained by the receiver.
    pub fn execute(
        &mut self,
        identity: &Identity,
        owner: &str,
        container: &str,
        incarnation: &str,
        dispatch: &Value,
        run: impl FnOnce() -> StoreResult<(u16, Value)>,
    ) -> StoreResult<Reply> {
        let _lock = self.lock()?;
        if identity
            .envelope
            .dispatch(&identity.selected)
            .map_err(StoreError::Conflict)?
            != dispatch
        {
            return Err(StoreError::Conflict(
                "native delivery differs from its retained dispatch".into(),
            ));
        }
        let admitted = self.transact(identity, |state| {
            if state.owner.as_ref().map(|o| o.owner_id.as_str()) != Some(owner)
                || state.container_id.as_deref() != Some(container)
            {
                return Err(StoreError::Conflict(
                    "native delivery has no matching physical binding".into(),
                ));
            }
            let decision = state.transition(json!({"op":"admit","incarnation":incarnation}))?;
            Ok((false, Some(decision)))
        })?;
        if admitted
            .decision
            .as_ref()
            .and_then(|a| a["action"].as_str())
            != Some("execute")
        {
            return Ok(admitted);
        }
        let (status, body) = run()?;
        self.transact(identity, |state| {
            state.transition(
                json!({"op":"complete","incarnation":incarnation,"status":status,"body":body}),
            )?;
            state.receipt = decoded(exec_invocation::complete_json(
                &serde_json::to_string(&identity.selected)?,
                &serde_json::to_string(&identity.envelope)?,
                &state.receipt.to_string(),
                status,
                &body.to_string(),
            ))?;
            Ok((false, None))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        path: PathBuf,
        identity: Identity,
        owner: Owner,
        container: String,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "whip-native-authority-{}-{}-{}.sqlite",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let selected = Invocation {
                instance_id: "native-controller-test".into(),
                effect_id: "exec".into(),
                attempt_admission_event_id: None,
            };
            let identity = Identity {
                envelope: Envelope::new(
                    selected.clone(),
                    json!({"protocol":"whip-executor/1", "effect_id":"exec"}),
                )
                .expect("envelope"),
                selected,
            };
            let owner = Owner {
                protocol: whipplescript_store::exec_native_owner::PROTOCOL.into(),
                instance_id: identity.selected.instance_id.clone(),
                effect_id: "exec".into(),
                run_id: identity.selected.run_id(),
                tracking_event_id: "original-track".into(),
                daemon_id: "original-daemon".into(),
                image_id: format!("sha256:{}", "a".repeat(64)),
                owner_id: "original-owner".into(),
            };
            Self {
                path,
                identity,
                owner,
                container: "b".repeat(64),
            }
        }
        fn open(&self) -> Authority {
            Authority::open(&self.path).expect("open authority")
        }
        fn bind(&self) {
            let mut authority = self.open();
            assert!(
                authority
                    .apply(
                        &self.identity,
                        Command::Claim {
                            owner: self.owner.clone()
                        }
                    )
                    .expect("claim")
                    .create
            );
            authority
                .apply(
                    &self.identity,
                    Command::Bind {
                        owner: self.owner.clone(),
                        container_id: self.container.clone(),
                    },
                )
                .expect("bind");
        }
        fn execute(&self, run: impl FnOnce() -> (u16, Value)) -> StoreResult<Reply> {
            self.open().execute(
                &self.identity,
                &self.owner.owner_id,
                &self.container,
                "incarnation-one",
                self.identity
                    .envelope
                    .dispatch(&self.identity.selected)
                    .expect("dispatch"),
                || Ok(run()),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for path in [
                self.path.clone(),
                self.path.with_extension("lock"),
                PathBuf::from(format!("{}-wal", self.path.display())),
                PathBuf::from(format!("{}-shm", self.path.display())),
            ] {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[test]
    fn native_controller_cold_claim_never_recreates_or_rebinds() {
        let f = Fixture::new();
        f.bind();
        let mut authority = f.open();
        assert!(
            !authority
                .apply(
                    &f.identity,
                    Command::Claim {
                        owner: f.owner.clone()
                    }
                )
                .expect("replay")
                .create
        );
        let mut changed = f.owner.clone();
        changed.tracking_event_id = "restored-workflow-track".into();
        assert!(authority
            .apply(&f.identity, Command::Claim { owner: changed })
            .is_err());
        assert!(authority
            .apply(
                &f.identity,
                Command::Bind {
                    owner: f.owner.clone(),
                    container_id: "c".repeat(64)
                }
            )
            .is_err());
        let mut changed = f.identity.clone();
        changed.envelope = Envelope::new(
            changed.selected.clone(),
            json!({"protocol":"whip-executor/1","effect_id":"exec","different":true}),
        )
        .expect("envelope");
        assert_eq!(changed.controller_id(), f.identity.controller_id());
        assert!(authority.apply(&changed, Command::Read).is_err());
    }

    #[test]
    fn native_controller_early_fence_and_late_cleanup_binding() {
        let f = Fixture::new();
        let fenced = f
            .open()
            .apply(
                &f.identity,
                Command::Fence {
                    fence_id: "first-fence".into(),
                },
            )
            .expect("fence");
        assert_eq!(fenced.response["action"]["action"], "not_admitted");
        assert!(
            !f.open()
                .apply(
                    &f.identity,
                    Command::Claim {
                        owner: f.owner.clone()
                    }
                )
                .expect("closed claim")
                .create
        );
        assert!(f
            .open()
            .apply(
                &f.identity,
                Command::Bind {
                    owner: f.owner.clone(),
                    container_id: f.container.clone()
                }
            )
            .is_err());
        let late = Fixture::new();
        assert!(
            late.open()
                .apply(
                    &late.identity,
                    Command::Claim {
                        owner: late.owner.clone()
                    }
                )
                .expect("claim")
                .create
        );
        late.open()
            .apply(
                &late.identity,
                Command::Fence {
                    fence_id: "first-fence".into(),
                },
            )
            .expect("fence");
        late.open()
            .apply(
                &late.identity,
                Command::Bind {
                    owner: late.owner.clone(),
                    container_id: late.container.clone(),
                },
            )
            .expect("late binding");
        let result = late
            .execute(|| panic!("fenced receiver executed"))
            .expect("closed delivery");
        assert_eq!(result.response["action"]["action"], "not_admitted");
    }

    #[test]
    fn native_controller_receiver_retains_completion_across_cold_replay() {
        let f = Fixture::new();
        f.bind();
        let result = f
            .execute(|| (207, json!({"original":true})))
            .expect("execute");
        assert_eq!(result.response["action"]["action"], "replay");
        assert_eq!(result.response["action"]["status"], 207);
        let replay = f
            .execute(|| panic!("cold replay executed twice"))
            .expect("replay");
        assert_eq!(replay.response, result.response);
        let mut broken = replay.state.clone();
        broken.receipt["body"] = json!({"changed":true});
        assert!(broken.validate(&f.identity).is_err());
        broken = replay.state;
        broken.controller = None;
        assert!(broken.validate(&f.identity).is_err());
    }

    #[test]
    fn native_controller_interrupted_receiver_stays_pending() {
        let f = Fixture::new();
        f.bind();
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = f.execute(|| panic!("receiver died after admission"));
        }));
        assert!(interrupted.is_err());
        let pending = f
            .execute(|| panic!("interrupted receiver executed twice"))
            .expect("pending");
        assert_eq!(pending.response["action"]["action"], "pending");
    }

    #[test]
    fn native_controller_fence_preserves_receiver_completion() {
        let f = Fixture::new();
        f.bind();
        let result = f
            .execute(|| {
                let fence = f
                    .open()
                    .apply(
                        &f.identity,
                        Command::Fence {
                            fence_id: "original-fence".into(),
                        },
                    )
                    .expect("concurrent fence");
                assert_eq!(fence.response["action"]["action"], "fence_required");
                (200, json!({"completed_during_fence":true}))
            })
            .expect("retained completion");
        assert_eq!(result.response["action"]["action"], "replay");
        assert_eq!(
            result.response["action"]["body"],
            json!({"completed_during_fence":true})
        );
    }

    #[test]
    fn native_controller_failed_admission_writes_never_execute() {
        for table in ["native_controller_events", "native_controller_tip"] {
            for failure in ["IGNORE", "ABORT, 'injected failure'"] {
                let f = Fixture::new();
                f.bind();
                let mut authority = f.open();
                authority.connection.execute_batch(&format!("CREATE TRIGGER fail_write BEFORE INSERT ON {table} BEGIN SELECT RAISE({failure}); END;")).expect("inject write failure");
                assert!(authority
                    .execute(
                        &f.identity,
                        &f.owner.owner_id,
                        &f.container,
                        "incarnation-one",
                        f.identity
                            .envelope
                            .dispatch(&f.identity.selected)
                            .expect("dispatch"),
                        || panic!("uncommitted admission executed")
                    )
                    .is_err());
                authority
                    .connection
                    .execute_batch("DROP TRIGGER fail_write")
                    .expect("restore writes");
                assert_eq!(
                    authority
                        .apply(&f.identity, Command::Read)
                        .expect("rolled back")
                        .response["action"]["action"],
                    "absent"
                );
                assert_eq!(
                    f.execute(|| (200, json!({})))
                        .expect("fresh admission")
                        .response["action"]["action"],
                    "replay"
                );
            }
        }
    }

    #[test]
    fn native_controller_finish_waits_for_completion_custody() {
        let f = Fixture::new();
        f.bind();
        std::thread::scope(|scope| {
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let fixture = &f;
            let receiver = scope.spawn(move || {
                fixture.execute(|| {
                    entered_tx.send(()).expect("entered");
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .expect("release receiver");
                    (200, json!({"retained":true}))
                })
            });
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("admitted");
            let fenced = f
                .open()
                .apply(
                    &f.identity,
                    Command::Fence {
                        fence_id: "original-fence".into(),
                    },
                )
                .expect("fence");
            let barrier_id = fenced.state.barrier.as_ref().expect("barrier")["barrier_id"]
                .as_str()
                .expect("id")
                .to_owned();
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (finished_tx, finished_rx) = std::sync::mpsc::channel();
            let fixture = &f;
            let finisher = scope.spawn(move || {
                let mut authority = fixture.open();
                started_tx.send(()).expect("started");
                let result = authority.apply(
                    &fixture.identity,
                    Command::Finish {
                        container_id: fixture.container.clone(),
                        barrier_id,
                    },
                );
                finished_tx.send(()).expect("finished");
                result
            });
            started_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("finisher started");
            assert!(matches!(
                finished_rx.recv_timeout(std::time::Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            release_tx.send(()).expect("release");
            receiver
                .join()
                .expect("receiver thread")
                .expect("completion");
            let finished = finisher.join().expect("finisher thread").expect("finish");
            assert_eq!(finished.response["action"]["action"], "replay");
            assert_eq!(
                finished.response["action"]["body"],
                json!({"retained":true})
            );
            assert!(finished.response["action"]["termination"].is_object());
        });
    }

    #[test]
    fn native_controller_concurrent_claim_has_one_creation_grant() {
        let f = Fixture::new();
        // Initialize once; concurrent cold connections still compete for the
        // same SQLite write transaction and immutable owner assignment.
        drop(f.open());
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..4 {
                let fixture = &f;
                let barrier = &barrier;
                workers.push(scope.spawn(move || {
                    let mut authority = fixture.open();
                    barrier.wait();
                    authority
                        .apply(
                            &fixture.identity,
                            Command::Claim {
                                owner: fixture.owner.clone(),
                            },
                        )
                        .expect("concurrent claim")
                        .create
                }));
            }
            assert_eq!(
                workers
                    .into_iter()
                    .map(|worker| usize::from(worker.join().expect("claim thread")))
                    .sum::<usize>(),
                1
            );
        });
    }

    #[test]
    fn native_helper_retains_ambiguous_delivery_and_replays_without_transport() {
        use crate::native_controller_helper::{self, Request, Transport};
        struct Fake {
            fault: u8,
            calls: Vec<String>,
        }
        impl Transport for Fake {
            fn exchange(&mut self, path: &str, body: Option<&str>) -> StoreResult<String> {
                self.calls.push(path.into());
                if path == "/exec/incarnation" {
                    assert!(body.is_none());
                    if self.fault == 4 {
                        return Err(StoreError::Conflict("handshake transport failed".into()));
                    }
                    if self.fault == 5 {
                        return Ok("invalid handshake".into());
                    }
                    return Ok(whipplescript_kernel::exec_incarnation::handshake(
                        "original-process",
                    )
                    .expect("handshake"));
                }
                assert_eq!(path, "/exec/bound");
                whipplescript_kernel::exec_incarnation::read_delivery(
                    body.expect("delivery"),
                    "original-process",
                )
                .expect("exact delivery");
                match self.fault {
                    1 => Err(StoreError::Conflict(
                        "response lost after external execution".into(),
                    )),
                    2 => Ok("not a completion".into()),
                    3 => Ok(whipplescript_kernel::exec_incarnation::completion(
                        "foreign-process",
                        200,
                        json!({}),
                    )
                    .expect("foreign response")),
                    _ => Ok(whipplescript_kernel::exec_incarnation::completion(
                        "original-process",
                        200,
                        json!({"original":true}),
                    )
                    .expect("response")),
                }
            }
        }
        for fault in 0..6 {
            let f = Fixture::new();
            f.bind();
            let request = || Request::Deliver {
                identity: f.identity.clone(),
                owner: f.owner.owner_id.clone(),
                container_id: f.container.clone(),
            };
            let mut transport = Fake {
                fault,
                calls: Vec::new(),
            };
            let delivered =
                native_controller_helper::process(&mut f.open(), request(), &mut transport);
            assert_eq!(delivered.is_ok(), fault == 0);
            if fault >= 4 {
                assert_eq!(transport.calls, ["/exec/incarnation"]);
                assert_eq!(
                    f.open()
                        .apply(&f.identity, Command::Read)
                        .expect("pre-admission state")
                        .response["action"]["action"],
                    "absent"
                );
                transport.fault = 0;
                transport.calls.clear();
                native_controller_helper::process(&mut f.open(), request(), &mut transport)
                    .expect("safe handshake retry");
            }
            assert_eq!(transport.calls, ["/exec/incarnation", "/exec/bound"]);
            transport.calls.clear();
            let cold = native_controller_helper::process(&mut f.open(), request(), &mut transport)
                .expect("cold read");
            assert!(
                transport.calls.is_empty(),
                "cold replay contacted the executor"
            );
            assert_eq!(
                cold.response["action"]["action"],
                if fault == 0 || fault >= 4 {
                    "replay"
                } else {
                    "pending"
                }
            );
            if fault == 0 || fault >= 4 {
                assert_eq!(cold.response["action"]["body"], json!({"original":true}));
            }
            let wrong = Request::Deliver {
                identity: f.identity.clone(),
                owner: "replacement".into(),
                container_id: f.container.clone(),
            };
            assert!(
                native_controller_helper::process(&mut f.open(), wrong, &mut transport).is_err()
            );
            assert!(transport.calls.is_empty());
        }
    }

    #[test]
    fn native_controller_failed_completion_commit_stays_pending() {
        for table in ["native_controller_events", "native_controller_tip"] {
            for failure in ["IGNORE", "ABORT, 'injected completion failure'"] {
                let f = Fixture::new();
                f.bind();
                let result = f.execute(|| {
                    f.open().connection.execute_batch(&format!("CREATE TRIGGER fail_completion BEFORE INSERT ON {table} BEGIN SELECT RAISE({failure}); END;")).expect("inject completion failure");
                    (200, json!({"external_execution_happened":true}))
                });
                assert!(result.is_err());
                f.open()
                    .connection
                    .execute_batch("DROP TRIGGER fail_completion")
                    .expect("restore writes");
                let pending = f
                    .execute(|| panic!("failed completion caused another execution"))
                    .expect("pending");
                assert_eq!(pending.response["action"]["action"], "pending");
            }
        }
    }

    #[test]
    fn native_helper_rejects_bad_input_and_retains_lost_output() {
        use crate::native_controller_helper::{self, Request};
        let f = Fixture::new();
        for input in [b"{}".as_slice(), b"{\"op\":\"unknown\"}".as_slice()] {
            assert!(native_controller_helper::serve(&f.path, input, Vec::new()).is_err());
            assert!(!f.path.exists());
        }
        let mut oversized = vec![b' '; 16 * 1024 * 1024 + 1];
        oversized.extend(
            serde_json::to_vec(&Request::Control {
                identity: f.identity.clone(),
                command: Command::Read,
            })
            .expect("valid oversized request"),
        );
        assert!(
            native_controller_helper::serve(&f.path, oversized.as_slice(), Vec::new()).is_err()
        );
        assert!(!f.path.exists());
        struct LostOutput;
        impl std::io::Write for LostOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let input = serde_json::to_vec(&Request::Control {
            identity: f.identity.clone(),
            command: Command::Claim {
                owner: f.owner.clone(),
            },
        })
        .expect("request");
        assert!(native_controller_helper::serve(&f.path, input.as_slice(), LostOutput).is_err());
        let mut output = Vec::new();
        native_controller_helper::serve(&f.path, input.as_slice(), &mut output)
            .expect("cold claim");
        let replay: Value = serde_json::from_slice(&output).expect("reply");
        assert_eq!(replay["create"], false);
        assert_eq!(replay["state"]["owner"]["owner_id"], f.owner.owner_id);
    }

    #[test]
    fn native_controller_corrupted_history_refuses_recovery() {
        for mutation in [
            "DELETE FROM native_controller_events WHERE sequence=(SELECT MAX(sequence) FROM native_controller_events)",
            "DELETE FROM native_controller_tip",
            "UPDATE native_controller_events SET digest='changed' WHERE sequence=1",
            "UPDATE native_controller_events SET state_json='{}' WHERE sequence=1",
        ] {
            let f = Fixture::new();
            f.bind();
            f.open().connection.execute_batch(mutation).expect("corrupt history");
            assert!(f.open().apply(&f.identity, Command::Read).is_err(), "{mutation}");
        }
    }

    /// The two guards that say this authority belongs to this invocation,
    /// asserted BY THEIR WORDS. `is_err()` alone does not reach either: a
    /// later guard refuses the same calls, so a test that only asks whether
    /// the call failed passes with the guard gone. The nearby
    /// `tracking_event_id` case above is exactly that -- a non-empty
    /// replacement passes `check_owner` and is refused by "physical owner
    /// cannot be replaced" instead.
    ///
    /// Remove either and a controller acts on authority belonging to a
    /// different invocation, which is what sharing a persistent volume makes
    /// possible in the first place.
    #[test]
    fn native_controller_refuses_authority_from_another_invocation() {
        // A replaced identity: same controller id, different envelope, so the
        // refusal cannot be coming from an id mismatch.
        let f = Fixture::new();
        f.bind();
        let mut other = f.identity.clone();
        other.envelope = Envelope::new(
            other.selected.clone(),
            json!({"protocol":"whip-executor/1","effect_id":"exec","elsewhere":true}),
        )
        .expect("envelope");
        assert_eq!(other.controller_id(), f.identity.controller_id());
        let error = f
            .open()
            .apply(&other, Command::Read)
            .expect_err("a replaced identity is not this authority");
        assert!(
            format!("{error:?}").contains("authority cannot be replaced"),
            "unexpected refusal: {error:?}"
        );

        // Every field `check_owner` compares, one at a time, on the owner a
        // CLAIM carries. It runs before the stored-owner comparison, so on a
        // fresh authority it is the only guard that can refuse these.
        for (field, value) in [
            ("protocol", "whipplescript.exec.native-owner/v0"),
            ("instance_id", "another-instance"),
            ("effect_id", "another-effect"),
            ("run_id", "another-run"),
            ("owner_id", ""),
            ("tracking_event_id", ""),
        ] {
            let f = Fixture::new();
            let mut owner = f.owner.clone();
            match field {
                "protocol" => owner.protocol = value.into(),
                "instance_id" => owner.instance_id = value.into(),
                "effect_id" => owner.effect_id = value.into(),
                "run_id" => owner.run_id = value.into(),
                "owner_id" => owner.owner_id = value.into(),
                _ => owner.tracking_event_id = value.into(),
            }
            let error = f
                .open()
                .apply(&f.identity, Command::Claim { owner })
                .expect_err("an owner from elsewhere is not this invocation's");
            assert!(
                format!("{error:?}").contains("owner differs from its invocation"),
                "{field}: unexpected refusal: {error:?}"
            );
        }

        // The same claim with the owner untouched is admitted, so the six
        // refusals above are about the field and not about the fixture.
        let f = Fixture::new();
        assert!(
            f.open()
                .apply(
                    &f.identity,
                    Command::Claim {
                        owner: f.owner.clone()
                    }
                )
                .expect("an owner matching its invocation claims")
                .create
        );
    }
}
