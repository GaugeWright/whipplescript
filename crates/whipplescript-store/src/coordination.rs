//! Coordination resources: lease, ledger, counter (spec/coordination.md).
//!
//! Workspace-scoped like the work-item tracker: run stores are disposable
//! per experiment, shared coordination state is durable. Every operation is
//! one atomic transaction with a branchable outcome — no read-then-act
//! surface exists, by construction (principle 2). Holder lifetime + TTL
//! bound every held lease (principle 3); the caller passes the current
//! time/period so the clock stays at the worker boundary.

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

#[cfg(feature = "native")]
use crate::StoreError;
use crate::StoreResult;

pub const DEFAULT_COORDINATION_OWNER: &str = "shared";

/// Outcome of one atomic lease-acquire attempt. `Contended` is a normal,
/// branchable outcome, not an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquireOutcome {
    Held,
    Contended { holders: Vec<String> },
}

/// Outcome of one atomic counter consume. `Over` is a normal, branchable
/// outcome — downgrade, not crash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeOutcome {
    Ok { remaining: i64 },
    Over { remaining: i64 },
}

/// Serialize a consume outcome for the `coord_applied` crash-atomicity marker.
/// `variant:remaining` is stable and dependency-free (no serde on the store's
/// hot path); `parse_consume_outcome` is its exact inverse.
#[cfg(feature = "native")]
fn format_consume_outcome(outcome: &ConsumeOutcome) -> String {
    match outcome {
        ConsumeOutcome::Ok { remaining } => format!("Ok:{remaining}"),
        ConsumeOutcome::Over { remaining } => format!("Over:{remaining}"),
    }
}

#[cfg(feature = "native")]
fn parse_consume_outcome(recorded: &str) -> Option<ConsumeOutcome> {
    let (variant, remaining) = recorded.split_once(':')?;
    let remaining = remaining.parse::<i64>().ok()?;
    match variant {
        "Ok" => Some(ConsumeOutcome::Ok { remaining }),
        "Over" => Some(ConsumeOutcome::Over { remaining }),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRow {
    pub owner: String,
    pub resource: String,
    pub key: String,
    pub holder: String,
    pub acquired_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerEntry {
    pub owner: String,
    pub ledger: String,
    pub partition: String,
    pub seq: i64,
    pub payload_json: String,
    pub appended_by: String,
    pub appended_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterRow {
    pub owner: String,
    pub counter: String,
    pub key: String,
    pub consumed: i64,
    pub period: String,
}

#[cfg(feature = "native")]
pub struct CoordinationStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl CoordinationStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path)?;
        // Several workers open one shared coordination store, and the first of
        // them to arrive at a fresh file has to establish WAL against the
        // others. `establish_wal` is what survives that race.
        crate::establish_wal(&connection)?;
        Self::from_connection(connection)
    }

    /// In-memory coordination store, for tests that need a handle satisfying
    /// `Coordination` without a file. No WAL: `:memory:` has no journal to
    /// establish, and `establish_wal` exists for the multi-worker file race.
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> StoreResult<Self> {
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        ensure_partitioned_schema(&connection)?;
        Ok(Self { connection })
    }

    /// One atomic attempt: expire stale holders (TTL crash net), then either
    /// take a free slot or report the current holders. Re-acquiring a lease
    /// already held by the same holder is `Held` (idempotent worker retry).
    pub fn try_acquire(
        &mut self,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome> {
        self.try_acquire_for_owner(
            DEFAULT_COORDINATION_OWNER,
            resource,
            key,
            slots,
            ttl_seconds,
            holder,
        )
    }

    pub fn try_acquire_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome> {
        let owner = normalized_owner(owner);
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND expires_at <= datetime('now')",
            params![owner, resource, key],
        )?;
        let already_held: i64 = tx.query_row(
            "SELECT COUNT(*) FROM leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4",
            params![owner, resource, key, holder],
            |row| row.get(0),
        )?;
        if already_held > 0 {
            tx.commit()?;
            return Ok(AcquireOutcome::Held);
        }
        let holders: i64 = tx.query_row(
            "SELECT COUNT(*) FROM leases WHERE owner = ?1 AND resource = ?2 AND key = ?3",
            params![owner, resource, key],
            |row| row.get(0),
        )?;
        if holders < slots {
            tx.execute(
                "INSERT INTO leases (owner, resource, key, holder, expires_at) VALUES (?1, ?2, ?3, ?4, datetime('now', ?5))",
                params![owner, resource, key, holder, format!("+{ttl_seconds} seconds")],
            )?;
            tx.commit()?;
            return Ok(AcquireOutcome::Held);
        }
        let mut statement = tx.prepare(
            "SELECT holder FROM leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 ORDER BY acquired_at",
        )?;
        let current = statement
            .query_map(params![owner, resource, key], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        tx.commit()?;
        Ok(AcquireOutcome::Contended { holders: current })
    }

    pub fn release(&mut self, resource: &str, key: &str, holder: &str) -> StoreResult<bool> {
        self.release_for_owner(DEFAULT_COORDINATION_OWNER, resource, key, holder)
    }

    pub fn release_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        holder: &str,
    ) -> StoreResult<bool> {
        let owner = normalized_owner(owner);
        let changed = self.connection.execute(
            "DELETE FROM leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4",
            params![owner, resource, key, holder],
        )?;
        Ok(changed >= 1)
    }

    /// Extend a held lease's TTL before it expires (spec/coordination.md,
    /// lease-renew). One atomic UPDATE keyed by the holder: a still-live hold
    /// gets `expires_at` bumped to `now + ttl_seconds` and its new expiry is
    /// returned (`Renewed`); a lease this holder does not currently hold — or one
    /// already expired — matches no row and yields `None` (`NotHeld`).
    pub fn renew_lease_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<Option<String>> {
        let owner = normalized_owner(owner);
        let expires_at = self
            .connection
            .query_row(
                "UPDATE leases SET expires_at = datetime('now', ?5) \
                 WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4 \
                 AND expires_at > datetime('now') RETURNING expires_at",
                params![
                    owner,
                    resource,
                    key,
                    holder,
                    format!("+{ttl_seconds} seconds")
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(expires_at)
    }

    /// Instance-terminal release: a holder reaching a workflow terminal drops
    /// everything it held (principle 3).
    pub fn release_all_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        let changed = self
            .connection
            .execute("DELETE FROM leases WHERE holder = ?1", params![holder])?;
        Ok(changed)
    }

    /// Appends commute — there is no contention to resolve. `retain_seconds`
    /// prunes old entries in the same transaction (mandatory bounded growth).
    pub fn append(
        &mut self,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64> {
        self.append_for_owner(
            DEFAULT_COORDINATION_OWNER,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
        )
    }

    pub fn append_for_owner(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64> {
        self.append_for_owner_marked(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
            None,
        )
    }

    /// Crash-atomic append: applied at most once per `effect_id`. On replay
    /// (the effect was applied but its cross-database terminal did not commit
    /// before a crash) the recorded seq is returned and no second entry is
    /// written. See `coord_applied`. `None` is the un-guarded append.
    #[allow(clippy::too_many_arguments)]
    pub fn append_for_owner_idempotent(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
        effect_id: &str,
    ) -> StoreResult<i64> {
        self.append_for_owner_marked(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
            Some(effect_id),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_for_owner_marked(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
        effect_id: Option<&str>,
    ) -> StoreResult<i64> {
        let owner = normalized_owner(owner);
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(effect_id) = effect_id {
            if let Some(recorded) = tx
                .query_row(
                    "SELECT outcome_json FROM coord_applied WHERE owner = ?1 AND effect_id = ?2",
                    params![owner, effect_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                tx.commit()?;
                return recorded.parse::<i64>().map_err(|_| {
                    StoreError::Conflict(format!(
                        "corrupt coord_applied outcome for effect `{effect_id}`: `{recorded}`"
                    ))
                });
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO ledger_seq (owner, ledger, next_seq) VALUES (?1, ?2, 1)",
            params![owner, ledger],
        )?;
        let seq: i64 = tx.query_row(
            "UPDATE ledger_seq SET next_seq = next_seq + 1 WHERE owner = ?1 AND ledger = ?2 RETURNING next_seq - 1",
            params![owner, ledger],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO ledger_entries (owner, ledger, partition, seq, payload_json, appended_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![owner, ledger, partition, seq, payload_json, appended_by],
        )?;
        tx.execute(
            "DELETE FROM ledger_entries WHERE owner = ?1 AND ledger = ?2 AND appended_at <= datetime('now', ?3)",
            params![owner, ledger, format!("-{retain_seconds} seconds")],
        )?;
        if let Some(effect_id) = effect_id {
            tx.execute(
                "INSERT INTO coord_applied (owner, effect_id, outcome_json) VALUES (?1, ?2, ?3)",
                params![owner, effect_id, seq.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(seq)
    }

    /// One atomic consume with lazy reset (spec/coordination.md): the caller
    /// derives `period` from the worker's clock read; a rolled period zeroes
    /// the count in the same transaction as the consume. No scheduler.
    pub fn consume(
        &mut self,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner(
            DEFAULT_COORDINATION_OWNER,
            counter,
            key,
            amount,
            cap,
            period,
        )
    }

    pub fn consume_for_owner(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner_marked(owner, counter, key, amount, cap, period, None)
    }

    /// Crash-atomic consume: charged at most once per `effect_id`. On replay
    /// the recorded outcome (`Ok`/`Over` + remaining) is returned and the
    /// counter is NOT charged a second time, so a crash between the coordination
    /// commit and the instance-store terminal cannot double-charge the budget.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_for_owner_idempotent(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
        effect_id: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner_marked(owner, counter, key, amount, cap, period, Some(effect_id))
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_for_owner_marked(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
        effect_id: Option<&str>,
    ) -> StoreResult<ConsumeOutcome> {
        let owner = normalized_owner(owner);
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(effect_id) = effect_id {
            if let Some(recorded) = tx
                .query_row(
                    "SELECT outcome_json FROM coord_applied WHERE owner = ?1 AND effect_id = ?2",
                    params![owner, effect_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                tx.commit()?;
                return parse_consume_outcome(&recorded).ok_or_else(|| {
                    StoreError::Conflict(format!(
                        "corrupt coord_applied outcome for effect `{effect_id}`: `{recorded}`"
                    ))
                });
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO counters (owner, counter, key, consumed, period) VALUES (?1, ?2, ?3, 0, ?4)",
            params![owner, counter, key, period],
        )?;
        tx.execute(
            "UPDATE counters SET consumed = 0, period = ?4 WHERE owner = ?1 AND counter = ?2 AND key = ?3 AND period != ?4",
            params![owner, counter, key, period],
        )?;
        let consumed: i64 = tx.query_row(
            "SELECT consumed FROM counters WHERE owner = ?1 AND counter = ?2 AND key = ?3",
            params![owner, counter, key],
            |row| row.get(0),
        )?;
        // `amount` is workflow-authored, so guard the cap check against i64
        // overflow: a near-MAX amount would wrap `consumed + amount` negative,
        // passing the check and driving `consumed` negative — an unbounded
        // counter (silent cap bypass in release, panic in debug). checked_add
        // fails closed to `Over` (denied), never charging.
        let outcome = match consumed.checked_add(amount) {
            Some(total) if amount >= 0 && total <= cap => {
                tx.execute(
                    "UPDATE counters SET consumed = consumed + ?4 WHERE owner = ?1 AND counter = ?2 AND key = ?3",
                    params![owner, counter, key, amount],
                )?;
                ConsumeOutcome::Ok {
                    remaining: cap - total,
                }
            }
            _ => ConsumeOutcome::Over {
                remaining: (cap - consumed).max(0),
            },
        };
        if let Some(effect_id) = effect_id {
            tx.execute(
                "INSERT INTO coord_applied (owner, effect_id, outcome_json) VALUES (?1, ?2, ?3)",
                params![owner, effect_id, format_consume_outcome(&outcome)],
            )?;
        }
        tx.commit()?;
        Ok(outcome)
    }

    /// The current reset-period identifier, read from the store's clock at
    /// the worker boundary (the one place the clock is legal). The lazy
    /// counter reset compares it inside the consume transaction.
    pub fn ledger_positions_impl(&self) -> StoreResult<Vec<(String, String, i64)>> {
        let mut stmt = self
            .connection
            .prepare("SELECT owner, ledger, next_seq FROM ledger_seq ORDER BY owner, ledger")?;
        let mapped = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    pub fn list_leases(&self, resource: Option<&str>) -> StoreResult<Vec<LeaseRow>> {
        self.list_leases_for_owner(None, resource)
    }

    pub fn list_leases_for_owner(
        &self,
        owner: Option<&str>,
        resource: Option<&str>,
    ) -> StoreResult<Vec<LeaseRow>> {
        let mut statement = self.connection.prepare(
            "SELECT owner, resource, key, holder, acquired_at, expires_at FROM leases WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR resource = ?2) ORDER BY owner, resource, key, acquired_at",
        )?;
        let rows = statement
            .query_map(params![owner.map(normalized_owner), resource], |row| {
                Ok(LeaseRow {
                    owner: row.get(0)?,
                    resource: row.get(1)?,
                    key: row.get(2)?,
                    holder: row.get(3)?,
                    acquired_at: row.get(4)?,
                    expires_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_entries(
        &self,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        self.list_entries_for_owner(None, ledger, partition)
    }

    pub fn list_entries_for_owner(
        &self,
        owner: Option<&str>,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT owner, ledger, partition, seq, payload_json, appended_by, appended_at FROM ledger_entries WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR ledger = ?2) AND (?3 IS NULL OR partition = ?3) ORDER BY owner, ledger, seq",
        )?;
        let rows = statement
            .query_map(
                params![owner.map(normalized_owner), ledger, partition],
                |row| {
                    Ok(LedgerEntry {
                        owner: row.get(0)?,
                        ledger: row.get(1)?,
                        partition: row.get(2)?,
                        seq: row.get(3)?,
                        payload_json: row.get(4)?,
                        appended_by: row.get(5)?,
                        appended_at: row.get(6)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_counters(&self, counter: Option<&str>) -> StoreResult<Vec<CounterRow>> {
        self.list_counters_for_owner(None, counter)
    }

    pub fn list_counters_for_owner(
        &self,
        owner: Option<&str>,
        counter: Option<&str>,
    ) -> StoreResult<Vec<CounterRow>> {
        let mut statement = self.connection.prepare(
            "SELECT owner, counter, key, consumed, period FROM counters WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR counter = ?2) ORDER BY owner, counter, key",
        )?;
        let rows = statement
            .query_map(params![owner.map(normalized_owner), counter], |row| {
                Ok(CounterRow {
                    owner: row.get(0)?,
                    counter: row.get(1)?,
                    key: row.get(2)?,
                    consumed: row.get(3)?,
                    period: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// The coordination store as a backend-agnostic trait — the sans-IO store seam
/// (DR-0033 Phase 3). It lets a durable-object SQLite backend implement the same
/// lease / ledger / counter operations the native rusqlite store provides, so
/// the DO host can slot a second physical store in without the language
/// changing. Every operation is one atomic, branchable transaction
/// (spec/coordination.md) — no read-then-act surface.
///
/// The owner-parameterized methods are the primitives an implementation must
/// supply; the shared-owner convenience forms are provided and delegate to
/// [`DEFAULT_COORDINATION_OWNER`]. `CoordinationStore` implements this by
/// forwarding to its inherent methods, so existing callers are unaffected.
///
/// Snapshot/manifest note (experimentation-subsystem downstream requirement —
/// tracker § Downstream-customer note): the owner-scoped `list_*_for_owner`
/// reads here are the half a checkpoint manifest is built from. A future
/// `snapshot`/`restore` pair that pins coordination state in a consistent cut is
/// deferred until the checkpoint mechanism lands, so it is designed against a
/// real consumer rather than speculatively.
pub trait Coordination {
    fn try_acquire_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome>;

    fn release_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        holder: &str,
    ) -> StoreResult<bool>;

    /// Extend a held lease's TTL; returns the new `expires_at` on success,
    /// `None` when this holder does not hold the (still-live) lease.
    fn renew_lease_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<Option<String>>;

    fn release_all_for_holder(&mut self, holder: &str) -> StoreResult<usize>;

    fn append_for_owner(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64>;

    fn consume_for_owner(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome>;

    /// Crash-atomic `ledger.append`, applied at most once per `effect_id`.
    /// Native records an idempotency marker in the SAME coordination-database
    /// transaction as the append, so a crash before the effect's terminal
    /// commits (a physically separate database) cannot double-write on replay.
    /// The DEFAULT delegation is exactly-once already on hosts where the
    /// coordination write shares the instance store's single transaction (the
    /// Durable Object commits all writes atomically at its output gate), so they
    /// need no marker and inherit this.
    #[allow(clippy::too_many_arguments)]
    fn append_for_owner_idempotent(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
        effect_id: &str,
    ) -> StoreResult<i64> {
        let _ = effect_id;
        self.append_for_owner(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
        )
    }

    /// Crash-atomic `counter.consume`, charged at most once per `effect_id`.
    /// See [`Coordination::append_for_owner_idempotent`] for why native needs
    /// the marker and the DO does not.
    #[allow(clippy::too_many_arguments)]
    fn consume_for_owner_idempotent(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
        effect_id: &str,
    ) -> StoreResult<ConsumeOutcome> {
        let _ = effect_id;
        self.consume_for_owner(owner, counter, key, amount, cap, period)
    }

    /// The workspace-plane HIGH-WATER positions of the monotone ledger
    /// stores: (owner, ledger, last minted seq). One half of the two-plane
    /// consistent cut (vw note §9.3) — monotone stores snapshot by
    /// position, not by copy. Leases and counters are current-state (not
    /// monotone) and deliberately have no position.
    fn ledger_positions(&self) -> StoreResult<Vec<(String, String, i64)>>;

    fn list_leases_for_owner(
        &self,
        owner: Option<&str>,
        resource: Option<&str>,
    ) -> StoreResult<Vec<LeaseRow>>;

    fn list_entries_for_owner(
        &self,
        owner: Option<&str>,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>>;

    fn list_counters_for_owner(
        &self,
        owner: Option<&str>,
        counter: Option<&str>,
    ) -> StoreResult<Vec<CounterRow>>;

    // Shared-owner convenience forms (provided).

    fn try_acquire(
        &mut self,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome> {
        self.try_acquire_for_owner(
            DEFAULT_COORDINATION_OWNER,
            resource,
            key,
            slots,
            ttl_seconds,
            holder,
        )
    }

    fn release(&mut self, resource: &str, key: &str, holder: &str) -> StoreResult<bool> {
        self.release_for_owner(DEFAULT_COORDINATION_OWNER, resource, key, holder)
    }

    fn append(
        &mut self,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64> {
        self.append_for_owner(
            DEFAULT_COORDINATION_OWNER,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
        )
    }

    fn consume(
        &mut self,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner(
            DEFAULT_COORDINATION_OWNER,
            counter,
            key,
            amount,
            cap,
            period,
        )
    }

    fn list_leases(&self, resource: Option<&str>) -> StoreResult<Vec<LeaseRow>> {
        self.list_leases_for_owner(None, resource)
    }

    fn list_entries(
        &self,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        self.list_entries_for_owner(None, ledger, partition)
    }

    fn list_counters(&self, counter: Option<&str>) -> StoreResult<Vec<CounterRow>> {
        self.list_counters_for_owner(None, counter)
    }
}

#[cfg(feature = "native")]
impl Coordination for CoordinationStore {
    // Each method forwards to the inherent method of the same name; inherent
    // methods win `self.method()` resolution, so this is delegation, not
    // recursion (the `unconditional_recursion` lint guards the invariant).
    fn ledger_positions(&self) -> StoreResult<Vec<(String, String, i64)>> {
        self.ledger_positions_impl()
    }

    fn try_acquire_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        slots: i64,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<AcquireOutcome> {
        self.try_acquire_for_owner(owner, resource, key, slots, ttl_seconds, holder)
    }

    fn release_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        holder: &str,
    ) -> StoreResult<bool> {
        self.release_for_owner(owner, resource, key, holder)
    }

    fn renew_lease_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<Option<String>> {
        self.renew_lease_for_owner(owner, resource, key, ttl_seconds, holder)
    }

    fn release_all_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        self.release_all_for_holder(holder)
    }

    fn append_for_owner(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
    ) -> StoreResult<i64> {
        self.append_for_owner(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
        )
    }

    fn consume_for_owner(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner(owner, counter, key, amount, cap, period)
    }

    fn append_for_owner_idempotent(
        &mut self,
        owner: &str,
        ledger: &str,
        partition: &str,
        payload_json: &str,
        appended_by: &str,
        retain_seconds: i64,
        effect_id: &str,
    ) -> StoreResult<i64> {
        self.append_for_owner_idempotent(
            owner,
            ledger,
            partition,
            payload_json,
            appended_by,
            retain_seconds,
            effect_id,
        )
    }

    fn consume_for_owner_idempotent(
        &mut self,
        owner: &str,
        counter: &str,
        key: &str,
        amount: i64,
        cap: i64,
        period: &str,
        effect_id: &str,
    ) -> StoreResult<ConsumeOutcome> {
        self.consume_for_owner_idempotent(owner, counter, key, amount, cap, period, effect_id)
    }

    fn list_leases_for_owner(
        &self,
        owner: Option<&str>,
        resource: Option<&str>,
    ) -> StoreResult<Vec<LeaseRow>> {
        self.list_leases_for_owner(owner, resource)
    }

    fn list_entries_for_owner(
        &self,
        owner: Option<&str>,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        self.list_entries_for_owner(owner, ledger, partition)
    }

    fn list_counters_for_owner(
        &self,
        owner: Option<&str>,
        counter: Option<&str>,
    ) -> StoreResult<Vec<CounterRow>> {
        self.list_counters_for_owner(owner, counter)
    }
}

#[cfg(feature = "native")]
fn normalized_owner(owner: &str) -> &str {
    if owner.trim().is_empty() {
        DEFAULT_COORDINATION_OWNER
    } else {
        owner
    }
}

#[cfg(feature = "native")]
/// This store's schema generation. Bumped when its `CREATE TABLE` set
/// changes in a way an older build cannot read.
const SATELLITE_SCHEMA_VERSION: i64 = 1;

#[cfg(feature = "native")]
fn ensure_partitioned_schema(connection: &Connection) -> StoreResult<()> {
    // DR-0054 Phase B parity: this store had no schema stamp and no
    // downgrade guard, so an older binary read a newer file as whatever it
    // parsed. `SqliteStore` has refused that since Phase B.
    crate::stamp_satellite_schema(connection, "coordination", SATELLITE_SCHEMA_VERSION)?;
    if !table_exists(connection, "leases")? {
        create_leases_table(connection)?;
    } else if !column_exists(connection, "leases", "owner")? {
        migrate_leases_table(connection)?;
    }

    if !table_exists(connection, "ledger_entries")? {
        create_ledger_entries_table(connection)?;
    } else if !column_exists(connection, "ledger_entries", "owner")? {
        migrate_ledger_entries_table(connection)?;
    }

    if !table_exists(connection, "ledger_seq")? {
        create_ledger_seq_table(connection)?;
    } else if !column_exists(connection, "ledger_seq", "owner")? {
        migrate_ledger_seq_table(connection)?;
    }

    if !table_exists(connection, "counters")? {
        create_counters_table(connection)?;
    } else if !column_exists(connection, "counters", "owner")? {
        migrate_counters_table(connection)?;
    }

    // Crash-atomicity marker (idempotent counter.consume / ledger.append). The
    // native coordination store is a physically separate SQLite database from
    // the instance store that records the effect's terminal, so the mutation
    // and the terminal cannot share one transaction. Without a marker, a crash
    // between the two commits leaves the effect `queued` in the instance store,
    // it is re-claimed, and the mutation double-applies (double-charge / dup
    // ledger entry). This table records — in the SAME transaction as the
    // mutation — that `effect_id` was applied and what outcome it produced, so a
    // replay returns the recorded outcome instead of mutating again.
    if !table_exists(connection, "coord_applied")? {
        create_coord_applied_table(connection)?;
    }

    connection.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_leases_holder ON leases(holder);
        CREATE INDEX IF NOT EXISTS idx_ledger_partition ON ledger_entries(owner, ledger, partition, seq);
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn create_leases_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS leases (
            owner TEXT NOT NULL,
            resource TEXT NOT NULL,
            key TEXT NOT NULL,
            holder TEXT NOT NULL,
            acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (owner, resource, key, holder)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn create_ledger_entries_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS ledger_entries (
            owner TEXT NOT NULL,
            ledger TEXT NOT NULL,
            partition TEXT NOT NULL,
            seq INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            appended_by TEXT NOT NULL,
            appended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (owner, ledger, seq)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn create_ledger_seq_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS ledger_seq (
            owner TEXT NOT NULL,
            ledger TEXT NOT NULL,
            next_seq INTEGER NOT NULL,
            PRIMARY KEY (owner, ledger)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn create_counters_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS counters (
            owner TEXT NOT NULL,
            counter TEXT NOT NULL,
            key TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            period TEXT NOT NULL,
            PRIMARY KEY (owner, counter, key)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn create_coord_applied_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS coord_applied (
            owner TEXT NOT NULL,
            effect_id TEXT NOT NULL,
            outcome_json TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (owner, effect_id)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn migrate_leases_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        DROP TABLE IF EXISTS leases_unpartitioned;
        ALTER TABLE leases RENAME TO leases_unpartitioned;
        "#,
    )?;
    create_leases_table(connection)?;
    connection.execute(
        r#"
        INSERT INTO leases (owner, resource, key, holder, acquired_at, expires_at)
        SELECT ?1, resource, key, holder, acquired_at, expires_at
        FROM leases_unpartitioned
        "#,
        params![DEFAULT_COORDINATION_OWNER],
    )?;
    connection.execute_batch("DROP TABLE leases_unpartitioned;")?;
    Ok(())
}

#[cfg(feature = "native")]
fn migrate_ledger_entries_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        DROP INDEX IF EXISTS idx_ledger_partition;
        DROP TABLE IF EXISTS ledger_entries_unpartitioned;
        ALTER TABLE ledger_entries RENAME TO ledger_entries_unpartitioned;
        "#,
    )?;
    create_ledger_entries_table(connection)?;
    connection.execute(
        r#"
        INSERT INTO ledger_entries (
            owner,
            ledger,
            partition,
            seq,
            payload_json,
            appended_by,
            appended_at
        )
        SELECT ?1, ledger, partition, seq, payload_json, appended_by, appended_at
        FROM ledger_entries_unpartitioned
        "#,
        params![DEFAULT_COORDINATION_OWNER],
    )?;
    connection.execute_batch("DROP TABLE ledger_entries_unpartitioned;")?;
    Ok(())
}

#[cfg(feature = "native")]
fn migrate_ledger_seq_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        DROP TABLE IF EXISTS ledger_seq_unpartitioned;
        ALTER TABLE ledger_seq RENAME TO ledger_seq_unpartitioned;
        "#,
    )?;
    create_ledger_seq_table(connection)?;
    connection.execute(
        r#"
        INSERT INTO ledger_seq (owner, ledger, next_seq)
        SELECT ?1, ledger, next_seq
        FROM ledger_seq_unpartitioned
        "#,
        params![DEFAULT_COORDINATION_OWNER],
    )?;
    connection.execute_batch("DROP TABLE ledger_seq_unpartitioned;")?;
    Ok(())
}

#[cfg(feature = "native")]
fn migrate_counters_table(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        DROP TABLE IF EXISTS counters_unpartitioned;
        ALTER TABLE counters RENAME TO counters_unpartitioned;
        "#,
    )?;
    create_counters_table(connection)?;
    connection.execute(
        r#"
        INSERT INTO counters (owner, counter, key, consumed, period)
        SELECT ?1, counter, key, consumed, period
        FROM counters_unpartitioned
        "#,
        params![DEFAULT_COORDINATION_OWNER],
    )?;
    connection.execute_batch("DROP TABLE counters_unpartitioned;")?;
    Ok(())
}

#[cfg(feature = "native")]
fn table_exists(connection: &Connection, table: &str) -> StoreResult<bool> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[cfg(feature = "native")]
fn column_exists(connection: &Connection, table: &str, column: &str) -> StoreResult<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `payload_json` parsed for projections. A payload this build cannot parse
/// (for example one written by a newer encoder) surfaces as an error carrying
/// the entry's identity instead of silently projecting `Null` — a silent null
/// is indistinguishable from an empty payload and loses data without a trace
/// (DR-0054 Phase A).
pub fn entry_payload(entry: &LedgerEntry) -> StoreResult<Value> {
    serde_json::from_str(&entry.payload_json).map_err(|error| {
        crate::StoreError::Conflict(format!(
            "ledger entry {}/{}/{} seq {} has an unreadable payload: {error}",
            entry.owner, entry.ledger, entry.partition, entry.seq
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_payload_surfaces_an_unreadable_payload_with_row_identity() {
        let entry = LedgerEntry {
            owner: "shared".to_owned(),
            ledger: "decisions".to_owned(),
            partition: "main".to_owned(),
            seq: 7,
            payload_json: "not json".to_owned(),
            appended_by: "worker-1".to_owned(),
            appended_at: "2026-07-31 00:00:00".to_owned(),
        };
        let error = entry_payload(&entry).expect_err("unreadable payload must fail closed");
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains("shared/decisions/main seq 7"),
            "diagnostic must carry the entry identity: {rendered}"
        );
        assert!(
            rendered.contains("unreadable payload"),
            "diagnostic must name the failure: {rendered}"
        );

        let readable = LedgerEntry {
            payload_json: "{\"vote\":\"yes\"}".to_owned(),
            ..entry
        };
        assert_eq!(
            entry_payload(&readable).expect("well-formed payload parses"),
            serde_json::json!({"vote": "yes"})
        );
    }

    /// A temp directory removed when the binding drops, panic included. Owning
    /// the directory rather than the `.sqlite` file means the `-shm`/`-wal`
    /// sidecars go with it.
    struct TempStoreDir(std::path::PathBuf);

    impl TempStoreDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "whipplescript-coordination-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&dir).expect("create coordination temp dir");
            Self(dir)
        }

        fn store_path(&self) -> std::path::PathBuf {
            self.0.join("coordination.sqlite")
        }
    }

    impl Drop for TempStoreDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Every worker that opens one *fresh* shared store at once must come back
    /// with a usable store. The first open of a file is the only moment the
    /// journal mode is converted, and that conversion takes a brief exclusive
    /// lock that `busy_timeout` does not cover — so this is where a contended
    /// open used to fail outright with SQLITE_BUSY.
    ///
    /// Asserting the resulting journal mode is the point, not decoration: an
    /// open that "succeeded" without establishing WAL would leave the store in
    /// rollback-journal mode, where a writer excludes readers, and every
    /// concurrency property the coordination store claims rests on WAL.
    #[test]
    fn concurrent_first_open_initializes_schema_idempotently() {
        let dir = TempStoreDir::new("concurrent-first-open");
        let path = dir.store_path();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        std::thread::scope(|scope| {
            let handles = (0..16)
                .map(|_| {
                    let path = path.clone();
                    let barrier = std::sync::Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        let store =
                            CoordinationStore::open(path).map_err(|error| format!("{error:?}"))?;
                        let mode: String = store
                            .connection
                            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                            .map_err(|error| format!("{error:?}"))?;
                        Ok::<_, String>(mode)
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                let mode = handle
                    .join()
                    .expect("schema opener thread")
                    .expect("concurrent schema open");
                assert_eq!(
                    mode.to_ascii_lowercase(),
                    "wal",
                    "a contended first open must still leave the store in WAL",
                );
            }
        });
    }

    /// A store whose temp directory dies with it. `Deref`/`DerefMut` keep the
    /// 12 call sites unchanged: `let mut store = store(); store.append(..)`.
    struct TempStore {
        _dir: TempStoreDir,
        inner: CoordinationStore,
    }

    impl std::ops::Deref for TempStore {
        type Target = CoordinationStore;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl std::ops::DerefMut for TempStore {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    fn store() -> TempStore {
        let dir = TempStoreDir::new("test");
        let inner = CoordinationStore::open(dir.store_path()).expect("open store");
        TempStore { _dir: dir, inner }
    }

    /// The two-plane cut's coordination half: ledger positions are the
    /// monotone high-water marks, one per (owner, ledger), advancing with
    /// each append.
    #[test]
    fn ledger_positions_are_high_water_marks() {
        let mut store = store();
        assert!(store.ledger_positions_impl().expect("op").is_empty());
        store
            .append_for_owner("shared", "audit", "p1", "{}", "w1", 3600)
            .expect("append");
        store
            .append_for_owner("shared", "audit", "p1", "{}", "w1", 3600)
            .expect("append");
        store
            .append_for_owner("shared", "mail", "p1", "{}", "w1", 3600)
            .expect("append");
        let positions = store.ledger_positions_impl().expect("op");
        let audit = positions
            .iter()
            .find(|(_, ledger, _)| ledger == "audit")
            .expect("audit ledger");
        let mail = positions
            .iter()
            .find(|(_, ledger, _)| ledger == "mail")
            .expect("mail ledger");
        assert!(audit.2 > mail.2, "two appends outrank one: {positions:?}");
    }

    /// Crash-atomicity (ultracode #5): the coordination mutation and the
    /// instance-store terminal live in different databases and cannot share a
    /// transaction, so a crash between them replays the effect. The idempotent
    /// append is applied ONCE per effect_id: a replay returns the recorded seq
    /// and writes no second entry.
    #[test]
    fn idempotent_append_does_not_double_write_on_replay() {
        let mut store = store();
        let seq1 = store
            .append_for_owner_idempotent("shared", "audit", "p1", "{\"n\":1}", "w1", 3600, "eff-A")
            .expect("append");
        // Replay the SAME effect (terminal never committed -> re-claimed).
        let seq2 = store
            .append_for_owner_idempotent("shared", "audit", "p1", "{\"n\":1}", "w1", 3600, "eff-A")
            .expect("replay");
        assert_eq!(
            seq1, seq2,
            "replay returns the recorded seq, not a fresh one"
        );
        let entries = store
            .list_entries_for_owner(Some("shared"), Some("audit"), None)
            .expect("list");
        assert_eq!(
            entries.len(),
            1,
            "exactly one durable entry despite the replay: {entries:?}"
        );
        // A genuinely different effect still appends independently.
        let seq3 = store
            .append_for_owner_idempotent("shared", "audit", "p1", "{\"n\":2}", "w1", 3600, "eff-B")
            .expect("second effect");
        assert_ne!(seq3, seq1, "a distinct effect_id mints a fresh seq");
    }

    /// Crash-atomicity for counter.consume: a replayed consume is NOT charged
    /// twice, so the budget cannot be double-debited by a crash-and-retry.
    #[test]
    fn idempotent_consume_does_not_double_charge_on_replay() {
        let mut store = store();
        let first = store
            .consume_for_owner_idempotent("shared", "budget", "k", 3, 10, "2026-07", "eff-C")
            .expect("consume");
        assert_eq!(first, ConsumeOutcome::Ok { remaining: 7 });
        // Replay the same effect: remaining must be unchanged (charged once).
        let replay = store
            .consume_for_owner_idempotent("shared", "budget", "k", 3, 10, "2026-07", "eff-C")
            .expect("replay");
        assert_eq!(
            replay,
            ConsumeOutcome::Ok { remaining: 7 },
            "replay returns the recorded outcome, counter charged once"
        );
        // A distinct effect debits again from the once-charged 7.
        let second = store
            .consume_for_owner_idempotent("shared", "budget", "k", 3, 10, "2026-07", "eff-D")
            .expect("second consume");
        assert_eq!(
            second,
            ConsumeOutcome::Ok { remaining: 4 },
            "distinct effect debits from 7, not from a double-charged 4"
        );
    }

    /// An adversarial near-i64::MAX amount must not overflow the cap check:
    /// it fails closed to `Over` (denied), never wrapping `consumed` negative
    /// into an unbounded counter (and never panicking in debug).
    #[test]
    fn consume_rejects_an_overflowing_amount() {
        let mut store = store();
        let outcome = store
            .consume("budget", "k", i64::MAX, 10, "2026-07")
            .expect("consume");
        assert_eq!(outcome, ConsumeOutcome::Over { remaining: 10 });
        // The counter was not charged, so a legitimate consume still succeeds.
        assert_eq!(
            store.consume("budget", "k", 4, 10, "2026-07").expect("ok"),
            ConsumeOutcome::Ok { remaining: 6 }
        );
    }

    /// A replayed `Over` consume also returns its recorded verdict unchanged and
    /// does not perturb the counter.
    #[test]
    fn idempotent_consume_replays_the_over_verdict() {
        let mut store = store();
        let over = store
            .consume_for_owner_idempotent("shared", "budget", "k", 20, 10, "2026-07", "eff-E")
            .expect("consume");
        assert_eq!(over, ConsumeOutcome::Over { remaining: 10 });
        let replay = store
            .consume_for_owner_idempotent("shared", "budget", "k", 20, 10, "2026-07", "eff-E")
            .expect("replay");
        assert_eq!(replay, ConsumeOutcome::Over { remaining: 10 });
    }

    /// Mutual exclusion: at most `slots` holders per key, ever; contended
    /// attempts report the holders.
    #[test]
    fn lease_mutual_exclusion_and_release() {
        let mut store = store();
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 600, "ins_a")
                .expect("op"),
            AcquireOutcome::Held
        );
        // Same-holder re-acquire is idempotent.
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 600, "ins_a")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Contended {
                holders: vec!["ins_a".to_owned()]
            }
        );
        // Distinct keys never contend (typed entity domains).
        assert_eq!(
            store
                .try_acquire("deploy", "staging", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert!(store.release("deploy", "prod", "ins_a").expect("op"));
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Held
        );
    }

    /// Drive the store through the `Coordination` trait as a `dyn` object: proves
    /// the seam is object-safe (a boxed durable-object backend is legal) and that
    /// the provided shared-owner forms delegate to the required owner primitives
    /// exactly as the inherent methods do — the contract a DO backend satisfies.
    #[test]
    fn coordination_trait_seam_is_faithful() {
        let mut store = store();
        let coordination: &mut dyn Coordination = &mut *store;

        // Shared-owner convenience forms route through the owner primitives.
        assert_eq!(
            coordination
                .try_acquire("deploy", "prod", 1, 600, "ins_a")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            coordination
                .try_acquire("deploy", "prod", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Contended {
                holders: vec!["ins_a".to_owned()]
            }
        );
        assert!(coordination.release("deploy", "prod", "ins_a").expect("op"));

        // Ledger append + read-back through the trait.
        coordination
            .append("events", "p", "{\"n\":1}", "ins_a", 3600)
            .expect("op");
        let entries = coordination.list_entries(Some("events"), None).expect("op");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].payload_json, "{\"n\":1}");

        // Counter consume with a fixed period through the trait.
        assert_eq!(
            coordination
                .consume("budget", "k", 3, 5, "2026-07-03")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 2 }
        );
        assert_eq!(
            coordination
                .consume("budget", "k", 3, 5, "2026-07-03")
                .expect("op"),
            ConsumeOutcome::Over { remaining: 2 }
        );

        // Owner-scoped primitive + list read — the read a checkpoint manifest is
        // built from (the partitioned `<pkg>/<name>::X` owner).
        coordination
            .try_acquire_for_owner("pkg/wf::region", "slot", "eu", 1, 600, "ins_c")
            .expect("op");
        let leases = coordination
            .list_leases_for_owner(Some("pkg/wf::region"), None)
            .expect("op");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].holder, "ins_c");
    }

    /// An expired TTL frees the slot without an explicit release (crash net).
    #[test]
    fn lease_ttl_expiry_frees_slot() {
        let mut store = store();
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 0, "ins_dead")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            store
                .try_acquire("deploy", "prod", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Held
        );
    }

    /// N-slot semaphore: slots fill independently; terminal release drops
    /// every lease the holder had.
    #[test]
    fn lease_slots_and_holder_release() {
        let mut store = store();
        assert_eq!(
            store
                .try_acquire("pool", "gpu", 2, 600, "ins_a")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            store
                .try_acquire("pool", "gpu", 2, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert!(matches!(
            store
                .try_acquire("pool", "gpu", 2, 600, "ins_c")
                .expect("op"),
            AcquireOutcome::Contended { .. }
        ));
        assert_eq!(store.release_all_for_holder("ins_a").expect("op"), 1);
        assert_eq!(
            store
                .try_acquire("pool", "gpu", 2, 600, "ins_c")
                .expect("op"),
            AcquireOutcome::Held
        );
    }

    #[test]
    fn coordination_resources_are_partitioned_by_owner() {
        let mut store = store();
        assert_eq!(
            store
                .try_acquire_for_owner("local/Ship", "deploy", "prod", 1, 600, "ins_a")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            store
                .try_acquire_for_owner("local/Audit", "deploy", "prod", 1, 600, "ins_b")
                .expect("op"),
            AcquireOutcome::Held
        );
        assert_eq!(
            store
                .try_acquire_for_owner("local/Ship", "deploy", "prod", 1, 600, "ins_c")
                .expect("op"),
            AcquireOutcome::Contended {
                holders: vec!["ins_a".to_owned()]
            }
        );

        assert_eq!(
            store
                .consume_for_owner("local/Ship", "budget", "cust", 600, 1000, "2026-06-10")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 400 }
        );
        assert_eq!(
            store
                .consume_for_owner("local/Audit", "budget", "cust", 600, 1000, "2026-06-10")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 400 }
        );

        let ship_seq = store
            .append_for_owner("local/Ship", "decisions", "api", "{}", "ins_a", 3600)
            .expect("op");
        let audit_seq = store
            .append_for_owner("local/Audit", "decisions", "api", "{}", "ins_b", 3600)
            .expect("op");
        assert_eq!(ship_seq, 1);
        assert_eq!(audit_seq, 1);

        let ship_leases = store
            .list_leases_for_owner(Some("local/Ship"), Some("deploy"))
            .expect("list");
        assert_eq!(ship_leases.len(), 1);
        assert_eq!(ship_leases[0].owner, "local/Ship");
    }

    /// Appends are totally ordered per ledger and partition-filterable.
    #[test]
    fn ledger_append_order_and_partitions() {
        let mut store = store();
        let first = store
            .append("decisions", "api", r#"{"choice":"rest"}"#, "ins_a", 3600)
            .expect("op");
        let second = store
            .append("decisions", "ui", r#"{"choice":"react"}"#, "ins_b", 3600)
            .expect("op");
        assert!(second > first);
        let api = store
            .list_entries(Some("decisions"), Some("api"))
            .expect("op");
        assert_eq!(api.len(), 1);
        assert_eq!(api[0].appended_by, "ins_a");
        assert_eq!(
            store
                .list_entries(Some("decisions"), None)
                .expect("op")
                .len(),
            2
        );
    }

    /// Cap invariant with lazy reset: consumed never exceeds cap inside one
    /// period; a rolled period zeroes the count atomically with the consume.
    #[test]
    fn counter_cap_and_lazy_reset() {
        let mut store = store();
        assert_eq!(
            store
                .consume("budget", "cust-1", 600, 1000, "2026-06-10")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 400 }
        );
        assert_eq!(
            store
                .consume("budget", "cust-1", 600, 1000, "2026-06-10")
                .expect("op"),
            ConsumeOutcome::Over { remaining: 400 }
        );
        // The over-budget attempt consumed nothing.
        assert_eq!(
            store
                .consume("budget", "cust-1", 400, 1000, "2026-06-10")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 0 }
        );
        // Next period: lazy reset at the consume boundary.
        assert_eq!(
            store
                .consume("budget", "cust-1", 600, 1000, "2026-06-11")
                .expect("op"),
            ConsumeOutcome::Ok { remaining: 400 }
        );
    }

    #[test]
    fn open_migrates_unpartitioned_coordination_rows_to_shared_owner() {
        let dir = TempStoreDir::new("migration");
        let path = dir.store_path();
        {
            let connection = Connection::open(&path).expect("open raw");
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE leases (
                        resource TEXT NOT NULL,
                        key TEXT NOT NULL,
                        holder TEXT NOT NULL,
                        acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT NOT NULL,
                        PRIMARY KEY (resource, key, holder)
                    );
                    INSERT INTO leases (resource, key, holder, expires_at)
                    VALUES ('deploy', 'prod', 'ins_old', datetime('now', '+600 seconds'));

                    CREATE TABLE ledger_entries (
                        ledger TEXT NOT NULL,
                        partition TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        payload_json TEXT NOT NULL,
                        appended_by TEXT NOT NULL,
                        appended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (ledger, seq)
                    );
                    CREATE TABLE ledger_seq (
                        ledger TEXT PRIMARY KEY,
                        next_seq INTEGER NOT NULL
                    );
                    INSERT INTO ledger_seq (ledger, next_seq) VALUES ('decisions', 2);
                    INSERT INTO ledger_entries (ledger, partition, seq, payload_json, appended_by)
                    VALUES ('decisions', 'api', 1, '{"choice":"rest"}', 'ins_old');

                    CREATE TABLE counters (
                        counter TEXT NOT NULL,
                        key TEXT NOT NULL,
                        consumed INTEGER NOT NULL DEFAULT 0,
                        period TEXT NOT NULL,
                        PRIMARY KEY (counter, key)
                    );
                    INSERT INTO counters (counter, key, consumed, period)
                    VALUES ('budget', 'cust', 600, '2026-06-10');
                    "#,
                )
                .expect("seed legacy schema");
        }

        let store = CoordinationStore::open(&path).expect("open migrated");
        assert_eq!(
            store
                .list_leases_for_owner(Some(DEFAULT_COORDINATION_OWNER), Some("deploy"))
                .expect("leases")[0]
                .owner,
            DEFAULT_COORDINATION_OWNER
        );
        assert_eq!(
            store
                .list_entries_for_owner(Some(DEFAULT_COORDINATION_OWNER), Some("decisions"), None)
                .expect("entries")[0]
                .owner,
            DEFAULT_COORDINATION_OWNER
        );
        assert_eq!(
            store
                .list_counters_for_owner(Some(DEFAULT_COORDINATION_OWNER), Some("budget"))
                .expect("counters")[0]
                .owner,
            DEFAULT_COORDINATION_OWNER
        );
        let _ = std::fs::remove_file(path);
    }
}
