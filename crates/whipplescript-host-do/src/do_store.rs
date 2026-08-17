//! The durable-object runtime store: `RuntimeStore` implemented over the DO's
//! synchronous SQLite (`DoSql`), instead of native rusqlite. This is DR-0033
//! Phase 5's core store binding.
//!
//! STATUS: **all 87 `RuntimeStore` methods are ported and verified against real
//! SQLite** — every method's SQL runs against an actual engine because the tests
//! back `DoSql` with rusqlite. This covers the whole surface: the read/query
//! family (`list_*`/`get_*`/`status`), registration + manifest fan-out, skills,
//! inbox, evidence/diagnostic/artifact records, clock/time-obligation + dependency
//! queries, leases, fact derivation + batch admission, program-version + revision
//! management, the capability/profile policy + capacity engine (`claimable_effects`),
//! the transactional write-path core (`commit_rule`(+guard), the `complete_effect`
//! family, `start_run`, `cancel_effect`, `request_effect_cancellation`,
//! `activate_revision`, the revision compatibility analysis), and
//! `rebuild_projections` with its full `do_replay_*` suite (the write path in
//! replay form). Shared `do_*` helpers mirror the native inner helpers; a couple
//! of long paths (`commit_rule_inner`, `complete_effect_terminal_inner`,
//! `insert_effect_cancellation_request`) live as inherent methods.
//!
//! The DO runs the *same* SQL the native `SqliteStore` does; the DO's single-writer
//! per-invocation model provides the atomicity the native path gets from a rusqlite
//! transaction (the store methods never yield mid-sequence). What remains before
//! the Phase-5 store box closes is *live-DO* validation: a `DoSql` impl over the
//! real `state.storage.sql` in the `worker` crate, exercised end-to-end against an
//! actual Durable Object. The Rust side is complete and green (native tests +
//! clippy + `wasm32-unknown-unknown`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use whipplescript_store::coordination::{
    AcquireOutcome, ConsumeOutcome, Coordination, CounterRow, LeaseRow, LedgerEntry,
};
use whipplescript_store::items::{apply_overlay, ClaimOutcome, RenewOutcome, WorkItem, WorkItems};
use whipplescript_store::{NewEvent, RuntimeStore, StoreError, StoreResult, StoredEvent};
// The remaining ported methods reference the full set of store data types.
#[allow(unused_imports)]
use whipplescript_store::*;

/// A SQL scalar crossing the `DoSql` boundary (the DO SQL API speaks JSON-ish
/// scalars; this is the Rust mirror).
#[derive(Clone, Debug, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Text(String),
}

/// The DO\'s synchronous SQLite, as the store needs it: run a statement, or run a
/// query and get back rows of scalars. The Worker shell implements this over
/// `state.storage.sql`; tests implement it over rusqlite so the ported SQL is
/// verified against a real engine.
pub trait DoSql {
    /// Run one statement. `sql` must contain EXACTLY ONE — no semicolon-joined
    /// batch, even though the DO SQL API accepts one.
    ///
    /// The two implementations do not agree on anything wider: rusqlite refuses a
    /// multi-statement string outright ("Multiple statements provided") since
    /// 0.40, where it used to tolerate one. So a batch that the Worker shell runs
    /// happily fails under the rusqlite tests, and one statement per call is the
    /// only contract both backends honour. To clear several tables, loop.
    fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String>;
    /// Run one query and get back its rows. Single-statement, for the same reason
    /// as [`DoSql::execute`].
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String>;

    /// Publish an ephemeral live-turn observation to the shell (DR 0061).
    ///
    /// This rides the SQL handle because that handle is the one thing already
    /// threaded everywhere the turn does work, and because it is a synchronous
    /// call *out* of the kernel — which is what makes the states inside a single
    /// `step()` observable at all. Tool execution and summarization compaction
    /// both happen without yielding to the shell; without this seam the shell
    /// could only report them after they had finished, which is not an
    /// observation.
    ///
    /// `detail` carries the subject when the state has one — the tool's name for
    /// `running_tool`. Never durable, never ordered, never acknowledged: a host
    /// that drops every one of these still runs the turn correctly, so the
    /// default is to do nothing.
    fn activity(&self, _kind: &str, _detail: Option<&str>) {}
}

/// Share ONE `DoSql` handle across the store and the file plane (P1). Both must
/// hit the same DO SQLite; the test `RusqliteDoSql` wraps a non-`Clone`
/// `Connection`, so we share the handle via `Rc` rather than requiring `Clone`.
/// `DoSql` methods are `&self`, so `Rc<T>` forwards them directly.
impl<T: DoSql + ?Sized> DoSql for std::rc::Rc<T> {
    fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
        (**self).execute(sql, params)
    }
    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
        (**self).query(sql, params)
    }
    fn activity(&self, kind: &str, detail: Option<&str>) {
        (**self).activity(kind, detail)
    }
}

/// The production `DoStorage` (P1): the DO file plane's byte store, over the
/// same DO SQLite as the runtime store (shared via `Rc<DoSql>`). Small files
/// inline in the `files` table (key = flattened workspace path -> content); the
/// large-file spill tier is `TieredFileStore` layered on top. This is the live
/// counterpart to the test-only in-memory `MemStorage`.
pub struct DoSqlStorage<S: DoSql> {
    sql: S,
    key_prefix: String,
}

impl<S: DoSql> DoSqlStorage<S> {
    pub fn new(sql: S) -> Self {
        Self {
            sql,
            key_prefix: String::new(),
        }
    }

    /// Scope the flat DO file plane to one governed host instance. Runtime
    /// instance ids contain no slash, so this prefix cannot collide with a
    /// workspace path or another chat inside the same placement DO.
    pub fn for_instance(sql: S, instance_id: &str) -> Self {
        Self {
            sql,
            key_prefix: format!("{instance_id}/"),
        }
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.key_prefix)
    }
}

fn io_err(message: String) -> std::io::Error {
    std::io::Error::other(message)
}

impl<S: DoSql> crate::DoStorage for DoSqlStorage<S> {
    fn read_file(&self, key: &str) -> std::io::Result<Option<String>> {
        let key = self.key(key);
        let rows = self
            .sql
            .query("SELECT content FROM files WHERE key = ?1", &[text(&key)])
            .map_err(io_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn write_file(&self, key: &str, content: &str) -> std::io::Result<()> {
        let key = self.key(key);
        self.sql
            .execute(
                "INSERT INTO files (key, content) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET content = excluded.content",
                &[text(&key), text(content)],
            )
            .map_err(io_err)?;
        Ok(())
    }

    fn append_file(&self, key: &str, content: &str) -> std::io::Result<()> {
        let key = self.key(key);
        self.sql
            .execute(
                "INSERT INTO files (key, content) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET content = content || excluded.content",
                &[text(&key), text(content)],
            )
            .map_err(io_err)?;
        Ok(())
    }

    fn file_exists(&self, key: &str) -> bool {
        let key = self.key(key);
        self.sql
            .query("SELECT 1 FROM files WHERE key = ?1", &[text(&key)])
            .map(|rows| !rows.is_empty())
            .unwrap_or(false)
    }

    fn delete_file(&self, key: &str) -> std::io::Result<()> {
        let key = self.key(key);
        self.sql
            .execute("DELETE FROM files WHERE key = ?1", &[text(&key)])
            .map_err(io_err)?;
        Ok(())
    }
}

/// `RuntimeStore` over a `DoSql` backend — the durable-object store impl.
pub struct DoSqliteStore<Sql: DoSql> {
    pub sql: Sql,
}

impl<Sql: DoSql> DoSqliteStore<Sql> {
    pub fn new(sql: Sql) -> Self {
        Self { sql }
    }

    /// The `capability_bindings.provider` name bound for `capability` visible to
    /// the program running `instance_id` — a program-scoped row wins over a
    /// global `NULL` one; `None` when unbound (mirrors the native
    /// `SqliteStore::capability_bound_provider`). The DO capability dispatch
    /// reads this to route a `memory-provider`-bound effect to the real
    /// `DoMemoryStore` instead of the fixture.
    pub fn capability_bound_provider(
        &self,
        instance_id: &str,
        capability: &str,
    ) -> StoreResult<Option<String>> {
        let program_id = self
            .sql
            .query(
                "SELECT program_id FROM instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?
            .first()
            .map(|row| as_text(&row[0]))
            .unwrap_or_default();
        let rows = self
            .sql
            .query(
                "SELECT provider FROM capability_bindings \
                 WHERE capability = ?1 AND (program_id = ?2 OR program_id IS NULL) \
                 ORDER BY (program_id IS NULL) ASC LIMIT 1",
                &[text(capability), text(&program_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().and_then(|row| as_opt_text(&row[0])))
    }

    /// The earliest future due instant (unix milliseconds) across this
    /// instance's pending timed effects — creation-anchored `timeout_seconds`
    /// deadlines and explicit `$.deadline_at` instants (DR-0033 Phase 6). The
    /// DO shell sets its single wake-up alarm from this when the instance
    /// parks; `None` means nothing is scheduled.
    pub fn next_effect_due_epoch_ms(&self, instance_id: &str) -> StoreResult<Option<i64>> {
        // A due instant is only honest for an effect `advance_time` will actually
        // fire. A `timer.wait` whose upstream dependency is unsatisfied is NOT
        // fired by `due_time_effects` (its dep guard), so it must not be reported
        // here either — otherwise the shell schedules an alarm for a creation-
        // anchored deadline already in the past, Cloudflare runs it immediately,
        // the re-drive re-parks with the same past due, and the alarm busy-loops
        // (billed, zero progress) until the dependency resolves. This is the same
        // guard `due_time_effects` applies (do_store.rs:6613); keep them in step.
        let dependency_guard = "( e.kind != 'timer.wait' OR NOT EXISTS ( \
             SELECT 1 FROM effect_dependencies AS dependency \
             JOIN effects AS upstream ON upstream.effect_id = dependency.upstream_effect_id \
              AND upstream.instance_id = dependency.instance_id \
             WHERE dependency.instance_id = e.instance_id \
               AND dependency.downstream_effect_id = e.effect_id AND NOT ( \
                 (dependency.predicate = 'succeeds' AND upstream.status = 'completed') \
                 OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out')) \
                 OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out') \
                 OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled') \
                 OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled')) \
               ) \
           ) )";
        let query = format!(
            "SELECT MIN(due_epoch) FROM ( \
               SELECT (CAST(strftime('%s', e.created_at) AS INTEGER) + e.timeout_seconds) \
                 AS due_epoch FROM effects AS e \
                WHERE e.instance_id = ?1 AND e.timeout_seconds IS NOT NULL \
                  AND e.status NOT IN ('completed', 'failed', 'timed_out', 'cancelled') \
                  AND {dependency_guard} \
               UNION ALL \
               SELECT CAST(strftime('%s', json_extract(e.input_json, '$.deadline_at')) \
                 AS INTEGER) FROM effects AS e \
                WHERE e.instance_id = ?1 \
                  AND json_extract(e.input_json, '$.deadline_at') IS NOT NULL \
                  AND e.status NOT IN ('completed', 'failed', 'timed_out', 'cancelled') \
                  AND {dependency_guard} \
             )"
        );
        let rows = self
            .sql
            .query(&query, &[text(instance_id)])
            .map_err(sql_err)?;
        Ok(rows
            .first()
            .and_then(|row| as_opt_i64(&row[0]))
            .map(|epoch_seconds| epoch_seconds * 1000))
    }

    /// Records an effect-cancellation request (idempotent replay + open-request
    /// guard), its `effect.cancellation_requested` event, and the evidence with its
    /// link fan-out (event / effect / revision / active runs). Shared by
    /// `request_effect_cancellation` and `activate_revision`. Mirrors
    /// `insert_effect_cancellation_request_on`.
    fn insert_effect_cancellation_request(
        &self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView> {
        if let Some(idempotency_key) = request.idempotency_key {
            let existing = self
                .sql
                .query(
                    "SELECT request_id, instance_id, effect_id, revision_id, reason, requested_by, \
                     causation_event_id, status, idempotency_key, created_at, updated_at, \
                     resolved_by_event_id FROM effect_cancellation_requests \
                     WHERE instance_id = ?1 AND idempotency_key = ?2",
                    &[text(request.instance_id), text(idempotency_key)],
                )
                .map_err(sql_err)?;
            if let Some(row) = existing.first() {
                return Ok(effect_cancellation_request_from_row(row));
            }
        }
        if self.effect_has_open_cancellation_request(request.instance_id, request.effect_id)? {
            return Err(StoreError::Conflict(
                "effect already has an open cancellation request".to_owned(),
            ));
        }
        // Mint a request id (SQLite-side, same shape as random_id_on).
        let id_rows = self
            .sql
            .query(
                "SELECT ?1 || '_' || lower(hex(randomblob(16)))",
                &[text("ecr")],
            )
            .map_err(sql_err)?;
        let request_id = id_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("failed to mint request id".to_string()))?;
        let payload = serde_json::json!({
            "request_id": &request_id,
            "effect_id": request.effect_id,
            "revision_id": request.revision_id,
            "reason": request.reason,
            "requested_by": request.requested_by,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: request.instance_id,
                event_type: "effect.cancellation_requested",
                payload_json: &payload,
                source: "kernel",
                causation_id: request.causation_event_id.or(Some(request.effect_id)),
                correlation_id: request.revision_id,
                idempotency_key: request.idempotency_key,
            },
        )?;
        self.sql
            .execute(
                "INSERT INTO effect_cancellation_requests (request_id, instance_id, effect_id, \
                 revision_id, reason, requested_by, causation_event_id, status, idempotency_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'requested', ?8)",
                &[
                    text(&request_id),
                    text(request.instance_id),
                    text(request.effect_id),
                    opt_text(request.revision_id),
                    opt_text(request.reason),
                    text(request.requested_by),
                    opt_text(request.causation_event_id),
                    opt_text(request.idempotency_key),
                ],
            )
            .map_err(sql_err)?;
        let active_run_rows = self
            .sql
            .query(
                "SELECT run_id FROM runs WHERE instance_id = ?1 AND effect_id = ?2 \
                 AND status = 'running' ORDER BY started_at, run_id",
                &[text(request.instance_id), text(request.effect_id)],
            )
            .map_err(sql_err)?;
        let active_run_ids: Vec<String> = active_run_rows.iter().map(|r| as_text(&r[0])).collect();
        let evidence_metadata = serde_json::json!({
            "request_id": &request_id,
            "effect_id": request.effect_id,
            "revision_id": request.revision_id,
            "reason": request.reason,
            "requested_by": request.requested_by,
            "event_id": event.event_id,
            "active_run_ids": &active_run_ids,
        })
        .to_string();
        let evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: request.instance_id,
                kind: "effect.cancellation.requested",
                subject_type: "effect_cancellation_request",
                subject_id: &request_id,
                causation_id: Some(&event.event_id),
                correlation_id: request.revision_id,
                summary: Some("effect cancellation requested"),
                metadata_json: &evidence_metadata,
            },
        )?;
        let link = |target_type: &str, target_id: &str, relation: &str| {
            do_insert_evidence_link(
                &self.sql,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: request.instance_id,
                    target_type,
                    target_id,
                    relation,
                },
            )
        };
        link("event", &event.event_id, "requested")?;
        link("effect", request.effect_id, "requested_cancellation")?;
        if let Some(revision_id) = request.revision_id {
            link("workflow_revision", revision_id, "requested_by")?;
        }
        for run_id in &active_run_ids {
            link("run", run_id, "active_run")?;
        }
        let recorded = self
            .sql
            .query(
                "SELECT request_id, instance_id, effect_id, revision_id, reason, requested_by, \
                 causation_event_id, status, idempotency_key, created_at, updated_at, \
                 resolved_by_event_id FROM effect_cancellation_requests WHERE request_id = ?1",
                &[text(&request_id)],
            )
            .map_err(sql_err)?;
        recorded
            .first()
            .map(|r| effect_cancellation_request_from_row(r))
            .ok_or_else(|| StoreError::Conflict("cancellation request was not recorded".to_owned()))
    }

    /// Shared rule-commit path for `commit_rule` /
    /// `commit_rule_with_revision_guard`: record `rule.committed`, insert derived
    /// facts, consume triggering facts, insert queued effects + dependency edges,
    /// optionally record a workflow-terminal event + instance transition, and
    /// record the rule-commit evidence with its full link fan-out. Mirrors
    /// `commit_rule_inner`.
    fn commit_rule_inner(
        &self,
        commit: RuleCommit<'_>,
        guard: Option<RuleCommitRevisionGuard<'_>>,
    ) -> StoreResult<StoredEvent> {
        let status_rows = self
            .sql
            .query(
                "SELECT status FROM instances WHERE instance_id = ?1",
                &[text(commit.instance_id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = status_rows.first() {
            let status = as_text(&row[0]);
            if status != "running" {
                return Err(StoreError::Conflict(format!(
                    "instance is {status}; rule commits require a running instance"
                )));
            }
        }
        let (program_version_id, revision_epoch) =
            do_active_revision(&self.sql, commit.instance_id)?;
        if let Some(guard) = guard {
            if program_version_id.as_deref() != Some(guard.program_version_id)
                || revision_epoch != guard.revision_epoch
            {
                return Err(StoreError::Conflict(format!(
                    "active revision changed before rule commit (expected version {} epoch {}, got version {} epoch {})",
                    guard.program_version_id,
                    guard.revision_epoch,
                    program_version_id.as_deref().unwrap_or("<none>"),
                    revision_epoch
                )));
            }
        }
        let payload = rule_commit_payload(&commit, program_version_id.as_deref(), revision_epoch)?;
        // Replays are idempotent, collisions are bugs (native commit_rule_inner
        // parity): a re-lowering that reproduces a committed firing
        // byte-for-byte returns the stored commit and touches nothing — before
        // this guard, a replayed commit appended a duplicate `rule.committed`
        // event and then errored on the already-consumed facts, leaving the
        // duplicate behind (no rollback on this path). A DISTINCT payload on an
        // existing key stays a loud error.
        if let Some(key) = commit.idempotency_key {
            let existing = self
                .sql
                .query(
                    "SELECT event_id, sequence, payload_json FROM events \
                     WHERE instance_id = ?1 AND idempotency_key = ?2",
                    &[text(commit.instance_id), text(key)],
                )
                .map_err(sql_err)?;
            if let Some(row) = existing.first() {
                if as_text(&row[2]) == payload {
                    return Ok(StoredEvent {
                        event_id: as_text(&row[0]),
                        sequence: as_i64(&row[1]),
                    });
                }
                return Err(StoreError::Conflict(format!(
                    "rule commit idempotency key reused with a DIFFERENT payload \
                     (rule `{}`, key `{key}`): two distinct firings derived one \
                     commit key — this is a whip bug, please report it",
                    commit.rule
                )));
            }
        }
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: commit.instance_id,
                event_type: "rule.committed",
                payload_json: &payload,
                source: "kernel",
                causation_id: commit.trigger_event_id,
                correlation_id: None,
                idempotency_key: commit.idempotency_key,
            },
        )?;
        for mark in commit.marks {
            let mark_payload = serde_json::json!({
                "mark": mark,
                "site": commit.rule,
                "committed_event_id": event.event_id,
            })
            .to_string();
            let mark_key = format!("mark-reached:{mark}:{}", event.event_id);
            do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: commit.instance_id,
                    event_type: "mark.reached",
                    payload_json: &mark_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: None,
                    idempotency_key: Some(&mark_key),
                },
            )?;
        }
        for fact in commit.facts {
            do_insert_fact(
                &self.sql,
                commit.instance_id,
                commit.rule,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                fact,
            )?;
        }
        do_consume_facts(&self.sql, commit.instance_id, commit.consumed_fact_ids)?;
        for effect in commit.effects {
            do_insert_effect(
                &self.sql,
                commit.instance_id,
                commit.rule,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                effect,
            )?;
        }
        for dependency in commit.dependencies {
            do_insert_effect_dependency(&self.sql, commit.instance_id, commit.rule, dependency)?;
        }
        if let Some(terminal) = commit.terminal {
            let terminal_payload = workflow_terminal_payload(&commit, terminal)?;
            let terminal_event = do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: commit.instance_id,
                    event_type: terminal.kind.event_type(),
                    payload_json: &terminal_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: Some(commit.rule),
                    idempotency_key: terminal.idempotency_key,
                },
            )?;
            self.sql
                .execute(
                    "UPDATE instances SET status = ?1, last_event_id = ?2, \
                     last_error = CASE WHEN ?1 = 'failed' THEN ?3 ELSE last_error END, \
                     updated_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP \
                     WHERE instance_id = ?4",
                    &[
                        text(terminal.kind.instance_status()),
                        text(&terminal_event.event_id),
                        text(terminal.name),
                        text(commit.instance_id),
                    ],
                )
                .map_err(sql_err)?;
        }
        let evidence_metadata = serde_json::json!({
            "rule": commit.rule,
            "trigger_event_id": commit.trigger_event_id,
            "event_id": event.event_id,
            "program_version_id": program_version_id,
            "revision_epoch": revision_epoch,
            "facts": commit.facts.iter().map(|fact| fact.fact_id).collect::<Vec<_>>(),
            "consumed_facts": commit.consumed_fact_ids,
            "effects": commit.effects.iter().map(|effect| effect.effect_id).collect::<Vec<_>>(),
            "terminal": commit.terminal.map(|terminal| serde_json::json!({
                "action": terminal.kind.action(),
                "name": terminal.name,
                "payload": serde_json::from_str::<Value>(terminal.payload_json).unwrap_or(Value::Null),
            })),
            "dependencies": commit
                .dependencies
                .iter()
                .map(|dependency| dependency.dependency_id)
                .collect::<Vec<_>>(),
        })
        .to_string();
        let evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: commit.instance_id,
                kind: "rule.committed",
                subject_type: "rule_commit",
                subject_id: &event.event_id,
                causation_id: commit.trigger_event_id,
                correlation_id: Some(commit.rule),
                summary: Some("rule committed facts and effects"),
                metadata_json: &evidence_metadata,
            },
        )?;
        let link = |target_type: &str, target_id: &str, relation: &str| {
            do_insert_evidence_link(
                &self.sql,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: commit.instance_id,
                    target_type,
                    target_id,
                    relation,
                },
            )
        };
        link("event", &event.event_id, "emitted")?;
        link("rule", commit.rule, "committed")?;
        for fact in commit.facts {
            link("fact", fact.fact_id, "recorded")?;
        }
        for fact_id in commit.consumed_fact_ids {
            link("fact", fact_id, "consumed")?;
        }
        for effect in commit.effects {
            link("effect", effect.effect_id, "queued")?;
        }
        for dependency in commit.dependencies {
            link("effect_dependency", dependency.dependency_id, "created")?;
        }
        Ok(event)
    }

    /// Shared terminal-completion path for `complete_effect` /
    /// `complete_effect_with_terminal_diagnostic` / `resolve_effect_uncertain`:
    /// record the `effect.terminal` event, transition the run (guarded against a
    /// double terminal), release the lease, transition the effect, resolve any
    /// cancellation requests, satisfy newly-unblocked dependencies, and optionally
    /// record a terminal diagnostic. Mirrors `complete_effect_terminal_inner`.
    fn complete_effect_terminal_inner(
        &self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
        run_status: &str,
    ) -> StoreResult<StoredEvent> {
        let payload = effect_completion_payload(&completion, diagnostic.as_ref())?;
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: completion.instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(completion.effect_id),
                correlation_id: None,
                idempotency_key: completion.idempotency_key,
            },
        )?;
        let updated_run = self
            .sql
            .execute(
                "UPDATE runs SET status = ?1, completed_at = CURRENT_TIMESTAMP, exit_code = ?2, \
                 summary = ?3, metadata_json = ?4 \
                 WHERE run_id = ?5 AND effect_id = ?6 AND instance_id = ?7 AND status = 'running'",
                &[
                    text(run_status),
                    completion.exit_code.map_or(SqlValue::Null, int),
                    opt_text(completion.summary),
                    text(completion.metadata_json),
                    text(completion.run_id),
                    text(completion.effect_id),
                    text(completion.instance_id),
                ],
            )
            .map_err(sql_err)?;
        if updated_run == 0 {
            let terminal_exists = !self
                .sql
                .query(
                    "SELECT 1 FROM runs WHERE run_id = ?1 AND effect_id = ?2 AND instance_id = ?3 \
                     AND status IN ('completed', 'failed', 'timed_out', 'cancelled', 'uncertain')",
                    &[
                        text(completion.run_id),
                        text(completion.effect_id),
                        text(completion.instance_id),
                    ],
                )
                .map_err(sql_err)?
                .is_empty();
            if terminal_exists {
                return Err(StoreError::Conflict(
                    "run already has a terminal completion".to_owned(),
                ));
            }
            return Err(StoreError::Conflict("run is not running".to_owned()));
        }
        self.sql
            .execute(
                "UPDATE leases SET status = 'released', released_at = CURRENT_TIMESTAMP \
                 WHERE run_id = ?1 AND effect_id = ?2 AND instance_id = ?3 AND status = 'active'",
                &[
                    text(completion.run_id),
                    text(completion.effect_id),
                    text(completion.instance_id),
                ],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "UPDATE effects SET status = ?1, updated_at = CURRENT_TIMESTAMP \
                 WHERE effect_id = ?2 AND instance_id = ?3",
                &[
                    text(completion.status),
                    text(completion.effect_id),
                    text(completion.instance_id),
                ],
            )
            .map_err(sql_err)?;
        do_mark_cancellation_requests_terminal(
            &self.sql,
            completion.instance_id,
            completion.effect_id,
            &event.event_id,
        )?;
        self.satisfy_dependencies(completion.instance_id)?;
        if let Some(diagnostic) = diagnostic {
            do_insert_diagnostic(
                &self.sql,
                DiagnosticRecord {
                    instance_id: Some(completion.instance_id),
                    program_id: diagnostic.program_id.as_deref(),
                    program_version_id: diagnostic.program_version_id.as_deref(),
                    severity: diagnostic.severity,
                    code: diagnostic.code.as_deref(),
                    message: &diagnostic.message,
                    source_span_json: diagnostic.source_span_json.as_deref(),
                    subject_type: diagnostic.subject_type.as_deref(),
                    subject_id: diagnostic.subject_id.as_deref(),
                    event_id: Some(&event.event_id),
                    effect_id: Some(completion.effect_id),
                    run_id: Some(completion.run_id),
                    assertion_id: diagnostic.assertion_id.as_deref(),
                    evidence_ids_json: &diagnostic.evidence_ids_json,
                    artifact_ids_json: &diagnostic.artifact_ids_json,
                    causation_id: diagnostic.causation_id.as_deref(),
                    correlation_id: diagnostic.correlation_id.as_deref(),
                    idempotency_key: diagnostic.idempotency_key.as_deref(),
                },
            )?;
        }
        Ok(event)
    }
}

pub(crate) fn sql_err(message: String) -> StoreError {
    StoreError::Io(std::io::Error::other(message))
}

pub(crate) fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.to_string())
}

pub(crate) fn opt_text(value: Option<&str>) -> SqlValue {
    match value {
        Some(v) => SqlValue::Text(v.to_string()),
        None => SqlValue::Null,
    }
}

pub(crate) fn as_i64(value: &SqlValue) -> i64 {
    match value {
        SqlValue::Int(n) => *n,
        _ => 0,
    }
}

pub(crate) fn as_text(value: &SqlValue) -> String {
    match value {
        SqlValue::Text(s) => s.clone(),
        _ => String::new(),
    }
}

pub(crate) fn as_opt_text(value: &SqlValue) -> Option<String> {
    match value {
        SqlValue::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_opt_i64(value: &SqlValue) -> Option<i64> {
    match value {
        SqlValue::Int(n) => Some(*n),
        _ => None,
    }
}

fn int(n: i64) -> SqlValue {
    SqlValue::Int(n)
}

/// SHA-256/128, byte-identical to the native store's `stable_hash_hex` — the DO
/// must compute the same skill/file `content_hash` the native path does so
/// content registered under either backend has a stable identity. (Swapped
/// from FNV-1a in the collision-hardening pass; keep the two in lockstep.)
pub(crate) fn stable_hash_hex(value: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Maps an 8-column skill row (`skill_id..required_capabilities`) to a `SkillView`.
fn skill_view_from_row(row: &[SqlValue]) -> SkillView {
    SkillView {
        skill_id: as_text(&row[0]),
        name: as_text(&row[1]),
        version: as_text(&row[2]),
        source: as_text(&row[3]),
        source_path: as_text(&row[4]),
        content_hash: as_text(&row[5]),
        description: as_text(&row[6]),
        required_capabilities_json: as_text(&row[7]),
    }
}

/// Maps a 10-column instance row to an `InstanceView`.
fn instance_view_from_row(row: &[SqlValue]) -> InstanceView {
    InstanceView {
        instance_id: as_text(&row[0]),
        program_id: as_text(&row[1]),
        version_id: as_text(&row[2]),
        revision_epoch: as_i64(&row[3]),
        workflow_principal: as_text(&row[4]),
        effective_authority_json: as_text(&row[5]),
        status: as_text(&row[6]),
        input_json: as_text(&row[7]),
        created_at: as_text(&row[8]),
        updated_at: as_text(&row[9]),
    }
}

/// Maps a 6-column event row to an `EventView`.
fn event_view_from_row(row: &[SqlValue]) -> EventView {
    EventView {
        event_id: as_text(&row[0]),
        sequence: as_i64(&row[1]),
        event_type: as_text(&row[2]),
        payload_json: as_text(&row[3]),
        source: as_text(&row[4]),
        occurred_at: as_text(&row[5]),
    }
}

/// Maps a 9-column fact row to a `FactView` (nullable: `program_version_id`,
/// `source_span_json`).
fn fact_view_from_row(row: &[SqlValue]) -> FactView {
    FactView {
        fact_id: as_text(&row[0]),
        program_version_id: as_opt_text(&row[1]),
        revision_epoch: as_i64(&row[2]),
        name: as_text(&row[3]),
        key: as_text(&row[4]),
        value_json: as_text(&row[5]),
        provenance_class: as_text(&row[6]),
        source_span_json: as_opt_text(&row[7]),
        source_event_id: as_opt_text(&row[8]).unwrap_or_default(),
    }
}

/// Maps a 14-column effect row to an `EffectView` (last column is the
/// `EXISTS(...)` cancel-requested flag, 0/1).
fn effect_view_from_row(row: &[SqlValue]) -> EffectView {
    EffectView {
        effect_id: as_text(&row[0]),
        kind: as_text(&row[1]),
        target: as_opt_text(&row[2]),
        input_json: as_text(&row[3]),
        status: as_text(&row[4]),
        created_by_rule: as_text(&row[5]),
        program_version_id: as_opt_text(&row[6]),
        revision_epoch: as_i64(&row[7]),
        profile: as_opt_text(&row[8]),
        required_capabilities_json: as_text(&row[9]),
        policy_block_reason: as_opt_text(&row[10]),
        policy_block_category: as_opt_text(&row[11]),
        declared_profiles_json: as_text(&row[12]),
        cancel_requested: as_i64(&row[13]) != 0,
    }
}

/// Maps a 9-column run row to a `RunView` (last column is the `EXISTS(...)`
/// cancel-requested flag, 0/1).
fn run_view_from_row(row: &[SqlValue]) -> RunView {
    RunView {
        run_id: as_text(&row[0]),
        effect_id: as_text(&row[1]),
        provider: as_text(&row[2]),
        worker_id: as_text(&row[3]),
        status: as_text(&row[4]),
        started_at: as_text(&row[5]),
        completed_at: as_opt_text(&row[6]),
        metadata_json: as_text(&row[7]),
        cancel_requested: as_i64(&row[8]) != 0,
    }
}

/// The 12-column instance-revision projection, used by the by-id / by-idempotency
/// revision lookups.
const REVISION_SELECT: &str = "SELECT revision_id, instance_id, epoch, from_version_id, \
     to_version_id, activated_by_event_id, activation_policy_json, cancellation_policy, status, \
     idempotency_key, created_at, activated_at FROM instance_revisions ";

/// A revision by its id, mirroring `revision_by_id_on`.
fn do_revision_by_id<Sql: DoSql>(
    sql: &Sql,
    revision_id: &str,
) -> StoreResult<Option<WorkflowRevisionView>> {
    let rows = sql
        .query(
            &format!("{REVISION_SELECT}WHERE revision_id = ?1"),
            &[text(revision_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|r| workflow_revision_from_row(r)))
}

/// A revision by its instance + idempotency key, mirroring
/// `revision_by_idempotency_on`.
fn do_revision_by_idempotency<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    idempotency_key: &str,
) -> StoreResult<Option<WorkflowRevisionView>> {
    let rows = sql
        .query(
            &format!("{REVISION_SELECT}WHERE instance_id = ?1 AND idempotency_key = ?2"),
            &[text(instance_id), text(idempotency_key)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|r| workflow_revision_from_row(r)))
}

/// Guards that a reused revision idempotency key carries identical activation
/// input, mirroring `ensure_revision_idempotency_matches`.
fn ensure_revision_idempotency_matches(
    existing: &WorkflowRevisionView,
    activation: &RevisionActivation<'_>,
    activation_policy: &Value,
    cancellation_policy: &str,
) -> StoreResult<()> {
    let existing_activation_policy: Value = serde_json::from_str(&existing.activation_policy_json)?;
    if existing.instance_id.as_str() == activation.instance_id
        && existing.from_version_id.as_str() == activation.from_version_id
        && existing.to_version_id.as_str() == activation.to_version_id
        && existing.cancellation_policy.as_str() == cancellation_policy
        && &existing_activation_policy == activation_policy
    {
        return Ok(());
    }
    Err(StoreError::Conflict(
        "revision idempotency key was reused with different activation input".to_owned(),
    ))
}

/// Normalizes a revision cancellation-policy token, mirroring
/// `normalize_cancellation_policy`.
fn normalize_cancellation_policy(policy: &str) -> StoreResult<&'static str> {
    match policy {
        "keep" => Ok("keep"),
        "cancel_queued" | "cancel queued" | "queued" => Ok("cancel_queued"),
        "request_running" | "request running" | "running" => Ok("request_running"),
        _ => Err(StoreError::Conflict(format!(
            "unsupported revision cancellation policy `{policy}`"
        ))),
    }
}

/// Effect ids a revision policy would act on: running effects (`running=true`) or
/// pending/blocked effects (`running=false`). Mirrors `revision_policy_effects_on`.
fn do_revision_policy_effects<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    running: bool,
) -> StoreResult<Vec<String>> {
    let predicate = if running {
        "status = 'running'"
    } else {
        "status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', \
         'blocked_by_capability', 'blocked_by_profile')"
    };
    let rows = sql
        .query(
            &format!(
                "SELECT effect_id FROM effects WHERE instance_id = ?1 AND {predicate} \
                 ORDER BY created_at, effect_id"
            ),
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.iter().map(|r| as_text(&r[0])).collect())
}

/// Maps a 12-column instance-revision row to a `WorkflowRevisionView`.
fn workflow_revision_from_row(row: &[SqlValue]) -> WorkflowRevisionView {
    WorkflowRevisionView {
        revision_id: as_text(&row[0]),
        instance_id: as_text(&row[1]),
        epoch: as_i64(&row[2]),
        from_version_id: as_text(&row[3]),
        to_version_id: as_text(&row[4]),
        activated_by_event_id: as_text(&row[5]),
        activation_policy_json: as_text(&row[6]),
        cancellation_policy: as_text(&row[7]),
        status: as_text(&row[8]),
        idempotency_key: as_opt_text(&row[9]),
        created_at: as_text(&row[10]),
        activated_at: as_text(&row[11]),
    }
}

/// Maps a 12-column cancellation-request row to an `EffectCancellationRequestView`.
fn effect_cancellation_request_from_row(row: &[SqlValue]) -> EffectCancellationRequestView {
    EffectCancellationRequestView {
        request_id: as_text(&row[0]),
        instance_id: as_text(&row[1]),
        effect_id: as_text(&row[2]),
        revision_id: as_opt_text(&row[3]),
        reason: as_opt_text(&row[4]),
        requested_by: as_text(&row[5]),
        causation_event_id: as_opt_text(&row[6]),
        status: as_text(&row[7]),
        idempotency_key: as_opt_text(&row[8]),
        created_at: as_text(&row[9]),
        updated_at: as_text(&row[10]),
        resolved_by_event_id: as_opt_text(&row[11]),
    }
}

/// Maps a 19-column workflow-invocation row (with parent/child active-version
/// joins) to a `WorkflowInvocationView`.
fn workflow_invocation_from_row(row: &[SqlValue]) -> WorkflowInvocationView {
    WorkflowInvocationView {
        invocation_id: as_text(&row[0]),
        parent_instance_id: as_text(&row[1]),
        parent_effect_id: as_text(&row[2]),
        parent_program_version_id: as_opt_text(&row[3]),
        parent_revision_epoch: as_i64(&row[4]),
        parent_active_program_version_id: as_opt_text(&row[5]),
        parent_active_revision_epoch: as_opt_i64(&row[6]),
        child_instance_id: as_text(&row[7]),
        child_program_version_id: as_opt_text(&row[8]),
        child_revision_epoch: as_opt_i64(&row[9]),
        child_active_program_version_id: as_opt_text(&row[10]),
        child_active_revision_epoch: as_opt_i64(&row[11]),
        target_workflow: as_text(&row[12]),
        input_json: as_text(&row[13]),
        status: as_text(&row[14]),
        terminal_event_id: as_opt_text(&row[15]),
        source_span_json: as_opt_text(&row[16]),
        created_at: as_text(&row[17]),
        updated_at: as_text(&row[18]),
    }
}

/// Maps a 7-column program-version row (joined with `programs.name`) to a
/// `ProgramVersionView`.
fn program_version_from_row(row: &[SqlValue]) -> ProgramVersionView {
    ProgramVersionView {
        program_id: as_text(&row[0]),
        program_name: as_text(&row[1]),
        version_id: as_text(&row[2]),
        source_hash: as_text(&row[3]),
        ir_hash: as_text(&row[4]),
        compiler_version: as_text(&row[5]),
        analysis_summary_json: as_text(&row[6]),
    }
}

/// Maps a 7-column artifact row to an `ArtifactView` (nullable: `content_hash`,
/// `mime_type`).
fn artifact_from_row(row: &[SqlValue]) -> ArtifactView {
    ArtifactView {
        artifact_id: as_text(&row[0]),
        run_id: as_text(&row[1]),
        kind: as_text(&row[2]),
        path: as_text(&row[3]),
        content_hash: as_opt_text(&row[4]),
        mime_type: as_opt_text(&row[5]),
        created_at: as_text(&row[6]),
    }
}

/// Maps an 11-column workspace row to a `WorkspaceView`.
fn workspace_from_row(row: &[SqlValue]) -> WorkspaceView {
    WorkspaceView {
        workspace_id: as_text(&row[0]),
        instance_id: as_opt_text(&row[1]),
        effect_id: as_opt_text(&row[2]),
        run_id: as_opt_text(&row[3]),
        provider: as_opt_text(&row[4]),
        policy: as_text(&row[5]),
        uri: as_text(&row[6]),
        status: as_text(&row[7]),
        metadata_json: as_text(&row[8]),
        created_at: as_text(&row[9]),
        updated_at: as_text(&row[10]),
    }
}

/// Maps a 20-column diagnostics row to a `DiagnosticView`.
fn diagnostic_from_row(row: &[SqlValue]) -> DiagnosticView {
    DiagnosticView {
        diagnostic_id: as_text(&row[0]),
        instance_id: as_opt_text(&row[1]),
        program_id: as_opt_text(&row[2]),
        program_version_id: as_opt_text(&row[3]),
        severity: as_text(&row[4]),
        code: as_opt_text(&row[5]),
        message: as_text(&row[6]),
        source_span_json: as_opt_text(&row[7]),
        subject_type: as_opt_text(&row[8]),
        subject_id: as_opt_text(&row[9]),
        event_id: as_opt_text(&row[10]),
        effect_id: as_opt_text(&row[11]),
        run_id: as_opt_text(&row[12]),
        assertion_id: as_opt_text(&row[13]),
        evidence_ids_json: as_text(&row[14]),
        artifact_ids_json: as_text(&row[15]),
        causation_id: as_opt_text(&row[16]),
        correlation_id: as_opt_text(&row[17]),
        idempotency_key: as_opt_text(&row[18]),
        created_at: as_text(&row[19]),
    }
}

/// Maps a 10-column evidence row to an `EvidenceView`.
fn evidence_from_row(row: &[SqlValue]) -> EvidenceView {
    EvidenceView {
        evidence_id: as_text(&row[0]),
        instance_id: as_text(&row[1]),
        kind: as_text(&row[2]),
        subject_type: as_text(&row[3]),
        subject_id: as_text(&row[4]),
        causation_id: as_opt_text(&row[5]),
        correlation_id: as_opt_text(&row[6]),
        summary: as_opt_text(&row[7]),
        metadata_json: as_text(&row[8]),
        created_at: as_text(&row[9]),
    }
}

/// Maps a 4-column time-effect row (`effect_id, kind, status, timeout_seconds`)
/// to a `DueTimeEffect`.
fn due_time_effect_from_row(row: &[SqlValue]) -> DueTimeEffect {
    DueTimeEffect {
        effect_id: as_text(&row[0]),
        kind: as_text(&row[1]),
        status: as_text(&row[2]),
        timeout_seconds: as_i64(&row[3]),
    }
}

/// Maps a 5-column evidence-link row to an `EvidenceLinkView`.
fn evidence_link_from_row(row: &[SqlValue]) -> EvidenceLinkView {
    EvidenceLinkView {
        evidence_id: as_text(&row[0]),
        target_type: as_text(&row[1]),
        target_id: as_text(&row[2]),
        relation: as_text(&row[3]),
        created_at: as_text(&row[4]),
    }
}

/// The shared 11-column workspace projection; callers append a WHERE/ORDER clause.
fn workspace_select_sql(predicate: &str) -> String {
    format!(
        "SELECT workspace_id, instance_id, effect_id, run_id, provider, policy, uri, status, \
         metadata_json, created_at, updated_at FROM workspaces {predicate}"
    )
}

/// Workspace-policy allow-list, mirroring the native validator.
fn validate_workspace_policy(policy: &str) -> StoreResult<()> {
    match policy {
        "shared"
        | "read_only"
        | "per_effect_worktree"
        | "per_issue_worktree"
        | "remote_sandbox" => Ok(()),
        _ => Err(StoreError::Conflict(format!(
            "unsupported workspace policy `{policy}`"
        ))),
    }
}

/// Workspace-status allow-list, mirroring the native validator.
fn validate_workspace_status(status: &str) -> StoreResult<()> {
    match status {
        "prepared" | "active" | "released" | "failed" => Ok(()),
        _ => Err(StoreError::Conflict(format!(
            "unsupported workspace status `{status}`"
        ))),
    }
}

/// JSON string value or `None`, mirroring the native `optional_string`.
fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

/// The first non-empty string among `fields`, or a `Conflict` error naming them.
/// Mirrors `required_manifest_string`.
fn required_manifest_string(value: &Value, fields: &[&str]) -> StoreResult<String> {
    fields
        .iter()
        .find_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            StoreError::Conflict(format!(
                "manifest entry must have one of these non-empty string fields: {}",
                fields
                    .iter()
                    .map(|field| format!("`{field}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// A string field or the empty string, mirroring `required_string`.
fn required_string(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Resolves a provider entry's effect kind from its aliases, mirroring
/// `manifest_effect_kind`.
fn manifest_effect_kind(provider: &Value) -> String {
    provider
        .get("effect_kind")
        .or_else(|| provider.get("core_effect_kind"))
        .or_else(|| provider.get("capability"))
        .or_else(|| provider.get("effect_contract"))
        .or_else(|| provider.get("effect_contract_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("capability.call")
        .to_owned()
}

/// Validates that `json` parses to a JSON array, mirroring `parse_json_array`.
fn parse_json_array(json: &str) -> StoreResult<()> {
    if serde_json::from_str::<Value>(json)?.is_array() {
        Ok(())
    } else {
        Err(StoreError::Conflict("expected JSON array".to_owned()))
    }
}

/// A `SkillView` as the metadata JSON the native `skill_to_json` emits.
/// Unreadable stored capabilities surface with the skill identity instead of
/// silently projecting `null` (native parity, DR-0054 Phase C).
fn skill_to_json(skill: &SkillView) -> StoreResult<Value> {
    let required_capabilities = serde_json::from_str::<Value>(&skill.required_capabilities_json)
        .map_err(|error| {
            StoreError::Conflict(format!(
                "skill `{}` ({}) has unreadable required_capabilities: {error}",
                skill.name, skill.skill_id
            ))
        })?;
    Ok(serde_json::json!({
        "skill_id": skill.skill_id,
        "name": skill.name,
        "version": skill.version,
        "source": skill.source,
        "source_path": skill.source_path,
        "content_hash": skill.content_hash,
        "description": skill.description,
        "required_capabilities": required_capabilities,
    }))
}

/// Appends an event with a per-instance monotonic sequence, returning its id +
/// sequence. Shared by the `append_event` trait method and the lifecycle methods
/// (which the native store threads through a transaction). Mirrors
/// `append_event_on`.
/// `do_append_event`, tolerant of an idempotency-key replay. Mirrors the
/// native `append_event_idempotent_on`: re-appending an event that already
/// exists (same instance, same idempotency key) returns the stored row instead
/// of a UNIQUE-constraint error.
fn do_append_event_idempotent<Sql: DoSql>(
    sql: &Sql,
    event: NewEvent<'_>,
) -> StoreResult<StoredEvent> {
    if let Some(key) = event.idempotency_key {
        let rows = sql
            .query(
                "SELECT event_id, sequence FROM events WHERE instance_id = ?1 AND idempotency_key = ?2",
                &[text(event.instance_id), text(key)],
            )
            .map_err(sql_err)?;
        if let Some(row) = rows.first() {
            return Ok(StoredEvent {
                event_id: as_text(&row[0]),
                sequence: as_i64(&row[1]),
            });
        }
    }
    do_append_event(sql, event)
}

fn do_append_event<Sql: DoSql>(sql: &Sql, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
    let rows = sql
        .query(
            "INSERT INTO events (event_id, instance_id, sequence, event_type, payload_json, \
             occurred_at, source, causation_id, correlation_id, idempotency_key, format_version) VALUES \
             ('evt_' || lower(hex(randomblob(16))), ?1, \
             (SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE instance_id = ?1), \
             ?2, ?3, CURRENT_TIMESTAMP, ?4, ?5, ?6, ?7, ?8) RETURNING event_id, sequence",
            &[
                text(event.instance_id),
                text(event.event_type),
                text(event.payload_json),
                text(event.source),
                opt_text(event.causation_id),
                opt_text(event.correlation_id),
                opt_text(event.idempotency_key),
                // DR-0054 Phase B: stamp the writer's event format (native
                // `append_event_on` parity); legacy NULL rows read as v1.
                int(whipplescript_store::SUPPORTED_EVENT_FORMAT_VERSION),
            ],
        )
        .map_err(|error| {
            // Name the colliding event (native `append_event_on` parity): a
            // UNIQUE hit on the idempotency key is undebuggable from a generic
            // store error.
            if error.contains("UNIQUE") {
                StoreError::Conflict(format!(
                    "duplicate event idempotency key for `{}` (key {:?}): a second \
                     distinct commit produced an already-used key",
                    event.event_type, event.idempotency_key
                ))
            } else {
                sql_err(error)
            }
        })?;
    let row = rows
        .first()
        .ok_or_else(|| sql_err("append_event returned no row".to_string()))?;
    Ok(StoredEvent {
        event_id: as_text(&row[0]),
        sequence: as_i64(&row[1]),
    })
}

/// Restorable-context RC-3: fold the file-store manifest at a cut from the
/// sequence-ordered `fact.derived` event payloads. Mirrors the native
/// `fold_file_manifest` verbatim (pure serde_json + `BTreeMap`): only
/// `file.write.completed` facts contribute, the RC-1 write descriptor lives at
/// `payload.value.value`, latest-write-wins per path, and the map serializes
/// deterministically (sorted by path) so identical file states hash identically.
fn do_fold_file_manifest(
    fact_payloads: &[String],
) -> StoreResult<(String, BTreeMap<String, String>)> {
    let mut manifest: BTreeMap<String, String> = BTreeMap::new();
    for payload_json in fact_payloads {
        let payload: Value = serde_json::from_str(payload_json)?;
        if payload.get("name").and_then(Value::as_str) != Some("file.write.completed") {
            continue;
        }
        let descriptor = payload.get("value").and_then(|fact| fact.get("value"));
        // Prefer the full resolved path (RC-5); fall back to relative `path`.
        let path = descriptor
            .and_then(|value| value.get("full_path").or_else(|| value.get("path")))
            .and_then(Value::as_str);
        let content_hash = descriptor
            .and_then(|value| value.get("content_hash"))
            .and_then(Value::as_str);
        if let (Some(path), Some(content_hash)) = (path, content_hash) {
            manifest.insert(path.to_owned(), content_hash.to_owned());
        }
    }
    let manifest_json = serde_json::to_string(&manifest)?;
    Ok((manifest_json, manifest))
}

/// RC-4c: the LIVE `fact.derived` payloads for an instance with the
/// restore-marker fold applied (RC-4b), mirroring native `live_fact_payloads_on`.
/// `up_to_sequence` bounds the read INCLUSIVE; `None` reads to the head.
fn do_live_fact_payloads<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    up_to_sequence: Option<i64>,
) -> StoreResult<Vec<String>> {
    let bound_clause = match up_to_sequence {
        Some(n) => format!(" AND sequence <= {n}"),
        None => String::new(),
    };
    let rows = sql
        .query(
            &format!(
                "SELECT event_type, payload_json, sequence FROM events \
                 WHERE instance_id = ?1 AND event_type IN ('fact.derived', 'context.restored'){bound_clause} \
                 ORDER BY sequence"
            ),
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    let mut live: Vec<(String, i64)> = Vec::new();
    for row in &rows {
        if as_text(&row[0]) == "context.restored" {
            if let Some(target) = do_restore_marker_target(&as_text(&row[1])) {
                live.retain(|(_, seq)| *seq <= target);
            }
        } else {
            live.push((as_text(&row[1]), as_i64(&row[2])));
        }
    }
    Ok(live.into_iter().map(|(payload, _)| payload).collect())
}

/// RC-4b: the target sequence a `context.restored` marker rewinds replay to.
/// Mirrors the native `restore_marker_target`: `None` for a malformed marker so
/// the fold applies no rewind rather than corrupting the projection.
fn do_restore_marker_target(payload_json: &str) -> Option<i64> {
    serde_json::from_str::<Value>(payload_json)
        .ok()?
        .get("restored_to_sequence")
        .and_then(Value::as_i64)
}

/// The `effect.terminal` event payload, mirroring `effect_completion_payload`.
/// Unreadable metadata surfaces with the run identity instead of writing `null`
/// into the canonical event (native parity, DR-0054 Phase C).
fn effect_completion_payload(
    completion: &EffectCompletion<'_>,
    diagnostic: Option<&TerminalDiagnosticRecord>,
) -> StoreResult<String> {
    let metadata = serde_json::from_str::<Value>(completion.metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` completion has unreadable metadata: {error}",
            completion.effect_id, completion.run_id
        ))
    })?;
    Ok(serde_json::json!({
        "effect_id": completion.effect_id,
        "run_id": completion.run_id,
        "provider": completion.provider,
        "worker_id": completion.worker_id,
        "status": completion.status,
        "exit_code": completion.exit_code,
        "summary": completion.summary,
        "metadata": metadata,
        "diagnostic": diagnostic.map(terminal_diagnostic_payload).transpose()?,
    })
    .to_string())
}

/// The nested diagnostic object in a terminal payload, mirroring
/// `terminal_diagnostic_payload`. An absent span is genuinely optional; a
/// present but unreadable span/ids field is corruption and surfaces instead of
/// silently degrading to `null` / `[]` (native parity, DR-0054 Phase C).
fn terminal_diagnostic_payload(diagnostic: &TerminalDiagnosticRecord) -> StoreResult<Value> {
    let context = |field: &str, error: serde_json::Error| {
        StoreError::Conflict(format!(
            "terminal diagnostic `{}` has unreadable {field}: {error}",
            diagnostic.message
        ))
    };
    Ok(serde_json::json!({
        "program_id": diagnostic.program_id,
        "program_version_id": diagnostic.program_version_id,
        "severity": diagnostic.severity.as_str(),
        "code": diagnostic.code,
        "message": diagnostic.message,
        "source_span": diagnostic
            .source_span_json
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .map_err(|error| context("source_span", error))?,
        "subject_type": diagnostic.subject_type,
        "subject_id": diagnostic.subject_id,
        "assertion_id": diagnostic.assertion_id,
        "evidence_ids": serde_json::from_str::<Value>(&diagnostic.evidence_ids_json)
            .map_err(|error| context("evidence_ids", error))?,
        "artifact_ids": serde_json::from_str::<Value>(&diagnostic.artifact_ids_json)
            .map_err(|error| context("artifact_ids", error))?,
        "causation_id": diagnostic.causation_id,
        "correlation_id": diagnostic.correlation_id,
        "idempotency_key": diagnostic.idempotency_key,
    }))
}

/// Resolves any open cancellation requests for an effect to `terminal`, mirroring
/// `mark_cancellation_requests_terminal_on`.
fn do_mark_cancellation_requests_terminal<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
    event_id: &str,
) -> StoreResult<()> {
    sql.execute(
        "UPDATE effect_cancellation_requests SET status = 'terminal', \
         resolved_by_event_id = ?1, updated_at = CURRENT_TIMESTAMP \
         WHERE instance_id = ?2 AND effect_id = ?3 AND status = 'requested'",
        &[text(event_id), text(instance_id), text(effect_id)],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// The execution fingerprint for a run: `H(input_json | sorted upstream ids)`,
/// mirroring `execution_fingerprint_on`.
fn do_execution_fingerprint<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<String> {
    let input_rows = sql
        .query(
            "SELECT input_json FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
            &[text(instance_id), text(effect_id)],
        )
        .map_err(sql_err)?;
    let input_json = input_rows
        .first()
        .map(|r| as_text(&r[0]))
        .unwrap_or_else(|| "{}".to_owned());
    let upstream_rows = sql
        .query(
            "SELECT upstream_effect_id FROM effect_dependencies \
             WHERE instance_id = ?1 AND downstream_effect_id = ?2",
            &[text(instance_id), text(effect_id)],
        )
        .map_err(sql_err)?;
    let mut upstream: Vec<String> = upstream_rows.iter().map(|r| as_text(&r[0])).collect();
    upstream.sort();
    Ok(stable_hash_hex(&format!(
        "{input_json}|{}",
        upstream.join(",")
    )))
}

/// The `effect.run_started` event payload, mirroring `run_start_payload`.
/// Unreadable metadata surfaces with the run identity instead of recording
/// `null` in the canonical event (native parity, DR-0054 Phase C).
fn run_start_payload(run: &RunStart<'_>, metadata_json: &str) -> StoreResult<String> {
    let metadata = serde_json::from_str::<Value>(metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` start has unreadable metadata: {error}",
            run.effect_id, run.run_id
        ))
    })?;
    Ok(serde_json::json!({
        "effect_id": run.effect_id,
        "run_id": run.run_id,
        "provider": run.provider,
        "worker_id": run.worker_id,
        "lease_id": run.lease_id,
        "lease_expires_at": run.lease_expires_at,
        "metadata": metadata,
    })
    .to_string())
}

/// Merge the execution fingerprint into a run's metadata object, mirroring
/// `inject_execution_fingerprint`: non-object but well-formed metadata still
/// normalizes to an object; unreadable metadata propagates instead of being
/// silently replaced with `{}` (native parity, DR-0054 Phase C).
fn inject_execution_fingerprint(
    run: &RunStart<'_>,
    metadata_json: &str,
    fingerprint: &str,
) -> StoreResult<String> {
    let mut value: Value = serde_json::from_str(metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` has unreadable metadata: {error}",
            run.effect_id, run.run_id
        ))
    })?;
    if !value.is_object() {
        value = serde_json::json!({});
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "execution_fingerprint".to_owned(),
            Value::String(fingerprint.to_owned()),
        );
    }
    Ok(value.to_string())
}

/// The active `(program_version_id, revision_epoch)` for an instance, or
/// `(None, 0)` when the instance row is absent. Mirrors `active_revision_on`.
fn do_active_revision<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
) -> StoreResult<(Option<String>, i64)> {
    let rows = sql
        .query(
            "SELECT version_id, revision_epoch FROM instances WHERE instance_id = ?1",
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    Ok(rows
        .first()
        .map(|r| (Some(as_text(&r[0])), as_i64(&r[1])))
        .unwrap_or((None, 0)))
}

/// Inserts a fact row (validating any `source_span_json`), mirroring `insert_fact`.
fn do_insert_fact<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    rule: &str,
    event_id: &str,
    program_version_id: Option<&str>,
    revision_epoch: i64,
    fact: &NewFact<'_>,
) -> StoreResult<()> {
    if let Some(source_span_json) = fact.source_span_json {
        serde_json::from_str::<Value>(source_span_json)?;
    }
    sql.execute(
        // Set-like collapse (native parity): the key is content-derived, so a
        // conflict is a byte-identical active fact — re-recording is a no-op.
        "INSERT INTO facts (fact_id, instance_id, program_version_id, revision_epoch, name, key, \
         value_json, source_event_id, source_rule, schema_id, provenance_class, correlation_id, \
         source_span_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
         ON CONFLICT(instance_id, name, key) DO UPDATE SET \
             consumed_at = NULL, fact_id = excluded.fact_id, \
             value_json = excluded.value_json, \
             source_event_id = excluded.source_event_id, source_rule = excluded.source_rule, \
             program_version_id = excluded.program_version_id, \
             revision_epoch = excluded.revision_epoch, updated_at = CURRENT_TIMESTAMP \
         WHERE facts.consumed_at IS NOT NULL",
        &[
            text(fact.fact_id),
            text(instance_id),
            opt_text(program_version_id),
            int(revision_epoch),
            text(fact.name),
            text(fact.key),
            text(fact.value_json),
            text(event_id),
            text(rule),
            opt_text(fact.schema_id),
            text(fact.provenance_class),
            opt_text(fact.correlation_id),
            opt_text(fact.source_span_json),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// Consumes each fact (marks `consumed_at`), erroring if any is already
/// inactive. Mirrors `consume_facts`.
fn do_consume_facts<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    fact_ids: &[&str],
) -> StoreResult<()> {
    for fact_id in fact_ids {
        let changed = sql
            .execute(
                "UPDATE facts SET consumed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND fact_id = ?2 AND consumed_at IS NULL",
                &[text(instance_id), text(fact_id)],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict(format!(
                "fact `{fact_id}` is not active and cannot be consumed"
            )));
        }
    }
    Ok(())
}

/// Inserts an effect row, mirroring `insert_effect`.
fn do_insert_effect<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    rule: &str,
    event_id: &str,
    program_version_id: Option<&str>,
    revision_epoch: i64,
    effect: &NewEffect<'_>,
) -> StoreResult<()> {
    sql.execute(
        "INSERT INTO effects (effect_id, instance_id, kind, target, input_json, status, \
         created_by_rule, created_by_event_id, program_version_id, revision_epoch, correlation_id, \
         idempotency_key, required_capabilities, profile, timeout_seconds) VALUES \
         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        &[
            text(effect.effect_id),
            text(instance_id),
            text(effect.kind),
            opt_text(effect.target),
            text(effect.input_json),
            text(effect.status),
            text(rule),
            text(event_id),
            opt_text(program_version_id),
            int(revision_epoch),
            opt_text(effect.correlation_id),
            text(effect.idempotency_key),
            text(effect.required_capabilities_json),
            opt_text(effect.profile),
            effect.timeout_seconds.map_or(SqlValue::Null, int),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// Inserts an effect dependency edge, mirroring `insert_effect_dependency`.
fn do_insert_effect_dependency<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    rule: &str,
    dependency: &NewEffectDependency<'_>,
) -> StoreResult<()> {
    sql.execute(
        "INSERT INTO effect_dependencies (dependency_id, instance_id, upstream_effect_id, \
         downstream_effect_id, predicate, created_by_rule) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            text(dependency.dependency_id),
            text(instance_id),
            text(dependency.upstream_effect_id),
            text(dependency.downstream_effect_id),
            text(dependency.predicate),
            text(rule),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// Re-queues `blocked_by_dependency` effects whose dependencies are now satisfied,
/// returning the count. Mirrors `satisfy_dependencies_on`.
fn do_satisfy_dependencies<Sql: DoSql>(sql: &Sql, instance_id: &str) -> StoreResult<usize> {
    let updated = sql
        .execute(
            "UPDATE effects SET status = 'queued', updated_at = CURRENT_TIMESTAMP \
             WHERE instance_id = ?1 AND status = 'blocked_by_dependency' \
             AND effect_id IN ( \
               SELECT candidate.effect_id FROM effects AS candidate \
               WHERE candidate.instance_id = ?1 AND NOT EXISTS ( \
                 SELECT 1 FROM effect_dependencies AS dependency \
                 JOIN effects AS upstream ON upstream.effect_id = dependency.upstream_effect_id \
                  AND upstream.instance_id = dependency.instance_id \
                 WHERE dependency.instance_id = candidate.instance_id \
                   AND dependency.downstream_effect_id = candidate.effect_id AND NOT ( \
                     (dependency.predicate = 'succeeds' AND upstream.status = 'completed') \
                     OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out')) \
                     OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out') \
                     OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled') \
                     OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled')) \
                   ) \
               ) \
             )",
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    Ok(updated as usize)
}

// ---------------------------------------------------------------------------
// Projection replay — one `do_replay_*` per persisted event type, reconstructing
// the facts / effects / runs / leases / revisions / cancellation-request
// projections from the append-only event log. Mirrors the native `replay_*`
// helpers; `rebuild_projections` deletes the projections and drives these.
// ---------------------------------------------------------------------------

fn do_replay_rule_commit<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let rule = payload
        .get("rule")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let commit_program_version_id = payload.get("program_version_id").and_then(Value::as_str);
    let commit_revision_epoch = payload
        .get("revision_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    for fact in payload
        .get("facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let value_json = fact
            .get("value")
            .map(Value::to_string)
            .unwrap_or_else(|| "{}".to_owned());
        let source_span_json = fact.get("source_span").map(Value::to_string);
        let program_version_id = fact
            .get("program_version_id")
            .and_then(Value::as_str)
            .or(commit_program_version_id);
        let revision_epoch = fact
            .get("revision_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(commit_revision_epoch);
        let new_fact = NewFact {
            fact_id: fact.get("fact_id").and_then(Value::as_str).unwrap_or(""),
            name: fact.get("name").and_then(Value::as_str).unwrap_or(""),
            key: fact.get("key").and_then(Value::as_str).unwrap_or(""),
            value_json: &value_json,
            schema_id: fact.get("schema_id").and_then(Value::as_str),
            provenance_class: fact
                .get("provenance_class")
                .and_then(Value::as_str)
                .unwrap_or("replayed"),
            correlation_id: fact.get("correlation_id").and_then(Value::as_str),
            source_span_json: source_span_json.as_deref(),
        };
        do_insert_fact(
            sql,
            instance_id,
            rule,
            event_id,
            program_version_id,
            revision_epoch,
            &new_fact,
        )?;
    }

    let consumed_fact_ids = payload
        .get("consumed_facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|fact| {
            fact.get("fact_id")
                .and_then(Value::as_str)
                .or_else(|| fact.as_str())
        })
        .collect::<Vec<_>>();
    do_consume_facts(sql, instance_id, &consumed_fact_ids)?;

    for effect in payload
        .get("effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let input_json = effect
            .get("input")
            .map(Value::to_string)
            .unwrap_or_else(|| "{}".to_owned());
        let required_capabilities_json = effect
            .get("required_capabilities")
            .map(Value::to_string)
            .unwrap_or_else(|| "[]".to_owned());
        let source_span_json = effect.get("source_span").map(Value::to_string);
        let program_version_id = effect
            .get("program_version_id")
            .and_then(Value::as_str)
            .or(commit_program_version_id);
        let revision_epoch = effect
            .get("revision_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(commit_revision_epoch);
        let new_effect = NewEffect {
            timeout_seconds: None,
            effect_id: effect
                .get("effect_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            kind: effect.get("kind").and_then(Value::as_str).unwrap_or(""),
            target: effect.get("target").and_then(Value::as_str),
            input_json: &input_json,
            status: effect
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("queued"),
            idempotency_key: effect
                .get("idempotency_key")
                .and_then(Value::as_str)
                .unwrap_or(""),
            required_capabilities_json: &required_capabilities_json,
            profile: effect.get("profile").and_then(Value::as_str),
            correlation_id: effect.get("correlation_id").and_then(Value::as_str),
            source_span_json: source_span_json.as_deref(),
        };
        do_insert_effect(
            sql,
            instance_id,
            rule,
            event_id,
            program_version_id,
            revision_epoch,
            &new_effect,
        )?;
    }

    for dependency in payload
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let new_dependency = NewEffectDependency {
            dependency_id: dependency
                .get("dependency_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            upstream_effect_id: dependency
                .get("upstream_effect_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            downstream_effect_id: dependency
                .get("downstream_effect_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            predicate: dependency
                .get("predicate")
                .and_then(Value::as_str)
                .unwrap_or("succeeds"),
        };
        do_insert_effect_dependency(sql, instance_id, rule, &new_dependency)?;
    }
    Ok(())
}

fn do_replay_fact_derived<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    source: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let fact_id = payload.get("fact_id").and_then(Value::as_str).unwrap_or("");
    let name = payload.get("name").and_then(Value::as_str).unwrap_or("");
    let key = payload.get("key").and_then(Value::as_str).unwrap_or("");
    if fact_id.is_empty() || name.is_empty() || key.is_empty() {
        return Ok(());
    }
    let value_json = payload
        .get("value")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let fact = NewFact {
        fact_id,
        name,
        key,
        value_json: &value_json,
        schema_id: payload.get("schema_id").and_then(Value::as_str),
        provenance_class: payload
            .get("provenance_class")
            .and_then(Value::as_str)
            .unwrap_or("derived"),
        correlation_id: payload.get("correlation_id").and_then(Value::as_str),
        source_span_json: None,
    };
    let (program_version_id, revision_epoch) = do_active_revision(sql, instance_id)?;
    do_insert_fact(
        sql,
        instance_id,
        source,
        event_id,
        program_version_id.as_deref(),
        revision_epoch,
        &fact,
    )
}

fn do_replay_workflow_terminal<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    event_type: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let status = payload
        .get("workflow_status")
        .and_then(Value::as_str)
        .unwrap_or({
            if event_type == "workflow.failed" {
                "failed"
            } else {
                "completed"
            }
        });
    let terminal_name = payload
        .get("terminal_name")
        .and_then(Value::as_str)
        .unwrap_or(event_type);
    sql.execute(
        "UPDATE instances SET status = ?1, last_event_id = ?2, \
         last_error = CASE WHEN ?1 = 'failed' THEN ?3 ELSE last_error END, \
         updated_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP WHERE instance_id = ?4",
        &[
            text(status),
            text(event_id),
            text(terminal_name),
            text(instance_id),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn do_replay_instance_transition<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let status = payload.get("status").and_then(Value::as_str).unwrap_or("");
    if status.is_empty() {
        return Ok(());
    }
    sql.execute(
        "UPDATE instances SET status = ?1, last_event_id = ?2, last_error = ?3, \
         updated_at = CURRENT_TIMESTAMP, completed_at = CASE \
         WHEN ?1 IN ('completed', 'cancelled') THEN CURRENT_TIMESTAMP ELSE completed_at END \
         WHERE instance_id = ?4",
        &[
            text(status),
            text(event_id),
            opt_text(payload.get("reason").and_then(Value::as_str)),
            text(instance_id),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn do_replay_revision_activation<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
    idempotency_key: Option<&str>,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let revision_id = payload
        .get("revision_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let from_version_id = payload
        .get("from_version_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let to_version_id = payload
        .get("to_version_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let epoch = payload
        .get("to_epoch")
        .and_then(Value::as_i64)
        .or_else(|| payload.get("revision_epoch").and_then(Value::as_i64))
        .unwrap_or(0);
    if revision_id.is_empty() || from_version_id.is_empty() || to_version_id.is_empty() {
        return Ok(());
    }
    let activation_policy_json = payload
        .get("activation_policy")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());
    let cancellation_policy = payload
        .get("cancellation_policy")
        .and_then(Value::as_str)
        .unwrap_or("keep");
    sql.execute(
        "INSERT INTO instance_revisions (revision_id, instance_id, epoch, from_version_id, \
         to_version_id, activated_by_event_id, activation_policy_json, cancellation_policy, status, \
         idempotency_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9) \
         ON CONFLICT(revision_id) DO NOTHING",
        &[
            text(revision_id),
            text(instance_id),
            int(epoch),
            text(from_version_id),
            text(to_version_id),
            text(event_id),
            text(&activation_policy_json),
            text(cancellation_policy),
            opt_text(idempotency_key),
        ],
    )
    .map_err(sql_err)?;
    sql.execute(
        "UPDATE instances SET version_id = ?1, revision_epoch = ?2, last_event_id = ?3, \
         updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?4",
        &[
            text(to_version_id),
            int(epoch),
            text(event_id),
            text(instance_id),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn do_replay_run_started<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    let lease_id = payload
        .get("lease_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if effect_id.is_empty() || run_id.is_empty() || lease_id.is_empty() {
        return Ok(());
    }
    let provider = payload
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let worker_id = payload
        .get("worker_id")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let lease_expires_at = payload
        .get("lease_expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let metadata_json = payload
        .get("metadata")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());
    sql.execute(
        "UPDATE effects SET status = 'running', policy_block_reason = NULL, \
         updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?1 AND effect_id = ?2 \
         AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')",
        &[text(instance_id), text(effect_id)],
    )
    .map_err(sql_err)?;
    sql.execute(
        "INSERT INTO runs (run_id, effect_id, instance_id, provider, worker_id, status, \
         metadata_json) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6) ON CONFLICT(run_id) DO UPDATE SET \
         effect_id = excluded.effect_id, instance_id = excluded.instance_id, \
         provider = excluded.provider, worker_id = excluded.worker_id, status = 'running', \
         completed_at = NULL, exit_code = NULL, summary = NULL, metadata_json = excluded.metadata_json",
        &[text(run_id), text(effect_id), text(instance_id), text(provider), text(worker_id), text(&metadata_json)],
    )
    .map_err(sql_err)?;
    sql.execute(
        "INSERT INTO leases (lease_id, run_id, effect_id, instance_id, worker_id, status, \
         expires_at) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6) ON CONFLICT(lease_id) DO UPDATE SET \
         run_id = excluded.run_id, effect_id = excluded.effect_id, instance_id = excluded.instance_id, \
         worker_id = excluded.worker_id, status = 'active', expires_at = excluded.expires_at, \
         released_at = NULL",
        &[text(lease_id), text(run_id), text(effect_id), text(instance_id), text(worker_id), text(lease_expires_at)],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn do_replay_effect_terminal<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    if effect_id.is_empty() {
        return Ok(());
    }
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("completed");
    let provider = payload
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let worker_id = payload
        .get("worker_id")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let metadata_json = payload
        .get("metadata")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());
    if !run_id.is_empty() {
        sql.execute(
            "INSERT INTO runs (run_id, effect_id, instance_id, provider, worker_id, status, \
             completed_at, exit_code, summary, metadata_json) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, ?7, ?8, ?9) ON CONFLICT(run_id) DO UPDATE SET \
             effect_id = excluded.effect_id, instance_id = excluded.instance_id, \
             provider = excluded.provider, worker_id = excluded.worker_id, status = excluded.status, \
             completed_at = CURRENT_TIMESTAMP, exit_code = excluded.exit_code, \
             summary = excluded.summary, metadata_json = excluded.metadata_json",
            &[
                text(run_id),
                text(effect_id),
                text(instance_id),
                text(provider),
                text(worker_id),
                text(status),
                payload.get("exit_code").and_then(Value::as_i64).map_or(SqlValue::Null, int),
                opt_text(payload.get("summary").and_then(Value::as_str)),
                text(&metadata_json),
            ],
        )
        .map_err(sql_err)?;
        sql.execute(
            "UPDATE leases SET status = 'released', released_at = CURRENT_TIMESTAMP \
             WHERE run_id = ?1 AND effect_id = ?2 AND instance_id = ?3 AND status = 'active'",
            &[text(run_id), text(effect_id), text(instance_id)],
        )
        .map_err(sql_err)?;
    }
    sql.execute(
        "UPDATE effects SET status = ?1, updated_at = CURRENT_TIMESTAMP \
         WHERE effect_id = ?2 AND instance_id = ?3",
        &[text(status), text(effect_id), text(instance_id)],
    )
    .map_err(sql_err)?;
    do_mark_cancellation_requests_terminal(sql, instance_id, effect_id, event_id)?;
    do_satisfy_dependencies(sql, instance_id)?;
    Ok(())
}

fn do_replay_effect_cancelled<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if effect_id.is_empty() {
        return Ok(());
    }
    sql.execute(
        "UPDATE effects SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP \
         WHERE instance_id = ?1 AND effect_id = ?2 \
         AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')",
        &[text(instance_id), text(effect_id)],
    )
    .map_err(sql_err)?;
    do_mark_cancellation_requests_terminal(sql, instance_id, effect_id, event_id)?;
    do_satisfy_dependencies(sql, instance_id)?;
    Ok(())
}

fn do_replay_lease_expired<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let lease_id = payload
        .get("lease_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if lease_id.is_empty() || run_id.is_empty() || effect_id.is_empty() {
        return Ok(());
    }
    sql.execute(
        "UPDATE leases SET status = 'expired', released_at = CURRENT_TIMESTAMP WHERE lease_id = ?1",
        &[text(lease_id)],
    )
    .map_err(sql_err)?;
    sql.execute(
        "UPDATE runs SET status = 'lease_expired', completed_at = CURRENT_TIMESTAMP \
         WHERE run_id = ?1 AND status = 'running'",
        &[text(run_id)],
    )
    .map_err(sql_err)?;
    sql.execute(
        "UPDATE effects SET status = 'queued', updated_at = CURRENT_TIMESTAMP \
         WHERE instance_id = ?1 AND effect_id = ?2 AND status = 'running'",
        &[text(instance_id), text(effect_id)],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn do_replay_cancellation_request<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
    idempotency_key: Option<&str>,
    causation_event_id: Option<&str>,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if request_id.is_empty() || effect_id.is_empty() {
        return Ok(());
    }
    // Prefer a real causation event, else anchor on this event.
    let resolved_causation = match causation_event_id {
        Some(candidate)
            if !sql
                .query(
                    "SELECT 1 FROM events WHERE instance_id = ?1 AND event_id = ?2",
                    &[text(instance_id), text(candidate)],
                )
                .map_err(sql_err)?
                .is_empty() =>
        {
            candidate
        }
        _ => event_id,
    };
    sql.execute(
        "INSERT INTO effect_cancellation_requests (request_id, instance_id, effect_id, revision_id, \
         reason, requested_by, causation_event_id, status, idempotency_key) VALUES \
         (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'requested', ?8) ON CONFLICT(request_id) DO NOTHING",
        &[
            text(request_id),
            text(instance_id),
            text(effect_id),
            opt_text(payload.get("revision_id").and_then(Value::as_str)),
            opt_text(payload.get("reason").and_then(Value::as_str)),
            text(payload.get("requested_by").and_then(Value::as_str).unwrap_or("replay")),
            text(resolved_causation),
            opt_text(idempotency_key),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// The workflow-terminal event payload, mirroring `workflow_terminal_payload`.
fn workflow_terminal_payload(
    commit: &RuleCommit<'_>,
    terminal: WorkflowTerminal<'_>,
) -> StoreResult<String> {
    let payload = serde_json::json!({
        "workflow_action": terminal.kind.action(),
        "workflow_status": terminal.kind.instance_status(),
        "terminal_name": terminal.name,
        "payload": serde_json::from_str::<Value>(terminal.payload_json)?,
        "rule": commit.rule,
    });
    serde_json::to_string(&payload).map_err(Into::into)
}

/// The `rule.committed` event payload, mirroring `rule_commit_payload`.
fn rule_commit_payload(
    commit: &RuleCommit<'_>,
    program_version_id: Option<&str>,
    revision_epoch: i64,
) -> StoreResult<String> {
    let facts = commit
        .facts
        .iter()
        .map(|fact| {
            if let Some(source_span_json) = fact.source_span_json {
                serde_json::from_str::<Value>(source_span_json)?;
            }
            Ok(serde_json::json!({
                "fact_id": fact.fact_id,
                "name": fact.name,
                "key": fact.key,
                "value": serde_json::from_str::<Value>(fact.value_json)?,
                "program_version_id": program_version_id,
                "revision_epoch": revision_epoch,
                "schema_id": fact.schema_id,
                "provenance_class": fact.provenance_class,
                "correlation_id": fact.correlation_id,
                "source_span": fact.source_span_json
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            }))
        })
        .collect::<StoreResult<Vec<_>>>()?;
    let consumed_facts = commit
        .consumed_fact_ids
        .iter()
        .map(|fact_id| serde_json::json!({ "fact_id": fact_id }))
        .collect::<Vec<_>>();
    let effects = commit
        .effects
        .iter()
        .map(|effect| {
            if let Some(source_span_json) = effect.source_span_json {
                serde_json::from_str::<Value>(source_span_json)?;
            }
            Ok(serde_json::json!({
                "effect_id": effect.effect_id,
                "kind": effect.kind,
                "target": effect.target,
                "input": serde_json::from_str::<Value>(effect.input_json)?,
                "status": effect.status,
                "program_version_id": program_version_id,
                "revision_epoch": revision_epoch,
                "idempotency_key": effect.idempotency_key,
                "required_capabilities": serde_json::from_str::<Value>(effect.required_capabilities_json)?,
                "profile": effect.profile,
                "correlation_id": effect.correlation_id,
                "source_span": effect.source_span_json
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            }))
        })
        .collect::<StoreResult<Vec<_>>>()?;
    let dependencies = commit
        .dependencies
        .iter()
        .map(|dependency| {
            serde_json::json!({
                "dependency_id": dependency.dependency_id,
                "upstream_effect_id": dependency.upstream_effect_id,
                "downstream_effect_id": dependency.downstream_effect_id,
                "predicate": dependency.predicate,
            })
        })
        .collect::<Vec<_>>();
    let terminal = match commit.terminal {
        Some(terminal) => Some(serde_json::from_str::<Value>(&workflow_terminal_payload(
            commit, terminal,
        )?)?),
        None => None,
    };
    let payload = serde_json::json!({
        "rule": commit.rule,
        "program_version_id": program_version_id,
        "revision_epoch": revision_epoch,
        "facts": facts,
        "consumed_facts": consumed_facts,
        "effects": effects,
        "dependencies": dependencies,
        "terminal": terminal,
        // DR-0043 slice 1 (mirrors the native payload): the firing's pinned
        // context, kernel-serialized.
        "context": commit
            .context_json
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()
            .map_err(StoreError::Json)?
            .unwrap_or(serde_json::Value::Null),
    });
    serde_json::to_string(&payload).map_err(Into::into)
}

/// Inserts an evidence link (idempotent on the natural key), mirroring
/// `insert_evidence_link_on`.
fn do_insert_evidence_link<Sql: DoSql>(sql: &Sql, link: EvidenceLink<'_>) -> StoreResult<()> {
    sql.execute(
        "INSERT INTO evidence_links (link_id, evidence_id, instance_id, target_type, target_id, \
         relation) VALUES ('evl_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(evidence_id, target_type, target_id, relation) DO NOTHING",
        &[
            text(link.evidence_id),
            text(link.instance_id),
            text(link.target_type),
            text(link.target_id),
            text(link.relation),
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// Inserts an evidence row plus its subject / causation / correlation links,
/// returning the generated id. Mirrors `insert_evidence_on`.
fn do_insert_evidence<Sql: DoSql>(sql: &Sql, evidence: EvidenceRecord<'_>) -> StoreResult<String> {
    serde_json::from_str::<Value>(evidence.metadata_json)?;
    let rows = sql
        .query(
            "INSERT INTO evidence (evidence_id, instance_id, kind, subject_type, subject_id, \
             causation_id, correlation_id, summary, metadata_json) VALUES \
             ('evd_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             RETURNING evidence_id",
            &[
                text(evidence.instance_id),
                text(evidence.kind),
                text(evidence.subject_type),
                text(evidence.subject_id),
                opt_text(evidence.causation_id),
                opt_text(evidence.correlation_id),
                opt_text(evidence.summary),
                text(evidence.metadata_json),
            ],
        )
        .map_err(sql_err)?;
    let evidence_id = rows
        .first()
        .map(|r| as_text(&r[0]))
        .ok_or_else(|| sql_err("insert_evidence returned no row".to_string()))?;
    do_insert_evidence_link(
        sql,
        EvidenceLink {
            evidence_id: &evidence_id,
            instance_id: evidence.instance_id,
            target_type: evidence.subject_type,
            target_id: evidence.subject_id,
            relation: "subject",
        },
    )?;
    if let Some(causation_id) = evidence.causation_id {
        do_insert_evidence_link(
            sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "causation",
                target_id: causation_id,
                relation: "caused_by",
            },
        )?;
    }
    if let Some(correlation_id) = evidence.correlation_id {
        do_insert_evidence_link(
            sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "correlation",
                target_id: correlation_id,
                relation: "correlates_with",
            },
        )?;
    }
    Ok(evidence_id)
}

/// Idempotency lookup for `record_diagnostic`, mirroring `existing_diagnostic_id_on`.
fn do_existing_diagnostic_id<Sql: DoSql>(
    sql: &Sql,
    diagnostic: &DiagnosticRecord<'_>,
) -> StoreResult<Option<String>> {
    let Some(idempotency_key) = diagnostic.idempotency_key else {
        return Ok(None);
    };
    let lookup = |where_clause: &str, params: &[SqlValue]| -> StoreResult<Option<String>> {
        let rows = sql
            .query(
                &format!("SELECT diagnostic_id FROM diagnostics WHERE {where_clause}"),
                params,
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| as_text(&r[0])))
    };
    if let Some(instance_id) = diagnostic.instance_id {
        return lookup(
            "instance_id = ?1 AND idempotency_key = ?2",
            &[text(instance_id), text(idempotency_key)],
        );
    }
    if let Some(program_version_id) = diagnostic.program_version_id {
        return lookup(
            "instance_id IS NULL AND program_version_id = ?1 AND idempotency_key = ?2",
            &[text(program_version_id), text(idempotency_key)],
        );
    }
    if let Some(program_id) = diagnostic.program_id {
        return lookup(
            "instance_id IS NULL AND program_id = ?1 AND idempotency_key = ?2",
            &[text(program_id), text(idempotency_key)],
        );
    }
    Ok(None)
}

/// Inserts a diagnostic (idempotent on `idempotency_key`), returning its id.
/// Mirrors `insert_diagnostic_on`.
fn do_insert_diagnostic<Sql: DoSql>(
    sql: &Sql,
    diagnostic: DiagnosticRecord<'_>,
) -> StoreResult<String> {
    if let Some(source_span_json) = diagnostic.source_span_json {
        serde_json::from_str::<Value>(source_span_json)?;
    }
    parse_json_array(diagnostic.evidence_ids_json)?;
    parse_json_array(diagnostic.artifact_ids_json)?;
    if let Some(existing_id) = do_existing_diagnostic_id(sql, &diagnostic)? {
        return Ok(existing_id);
    }
    let rows = sql
        .query(
            "INSERT INTO diagnostics (diagnostic_id, instance_id, program_id, \
             program_version_id, severity, code, message, source_span_json, subject_type, \
             subject_id, event_id, effect_id, run_id, assertion_id, evidence_ids_json, \
             artifact_ids_json, causation_id, correlation_id, idempotency_key) VALUES \
             ('dia_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) RETURNING diagnostic_id",
            &[
                opt_text(diagnostic.instance_id),
                opt_text(diagnostic.program_id),
                opt_text(diagnostic.program_version_id),
                text(diagnostic.severity.as_str()),
                opt_text(diagnostic.code),
                text(diagnostic.message),
                opt_text(diagnostic.source_span_json),
                opt_text(diagnostic.subject_type),
                opt_text(diagnostic.subject_id),
                opt_text(diagnostic.event_id),
                opt_text(diagnostic.effect_id),
                opt_text(diagnostic.run_id),
                opt_text(diagnostic.assertion_id),
                text(diagnostic.evidence_ids_json),
                text(diagnostic.artifact_ids_json),
                opt_text(diagnostic.causation_id),
                opt_text(diagnostic.correlation_id),
                opt_text(diagnostic.idempotency_key),
            ],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|r| as_text(&r[0]))
        .ok_or_else(|| sql_err("insert_diagnostic returned no row".to_string()))
}

// ---------------------------------------------------------------------------
// Revision compatibility-analysis suite — the structural diff + fact-typecheck
// the revision commands run to decide whether a candidate version is safe to
// activate against a live instance. The `validate_*` / `compare_*` / signature
// helpers are pure (serde_json + BTreeMap), copied verbatim from the native store;
// the three `do_*` helpers touch `DoSql`.
// ---------------------------------------------------------------------------

struct RevisionInstanceContext {
    program_id: String,
    program_name: String,
    active_version_id: String,
    status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContractSummary {
    ty: String,
    source_span_json: Option<String>,
}

fn revision_compatibility_diagnostic(
    code: &str,
    message: String,
    subject: Option<&str>,
) -> RevisionCompatibilityDiagnostic {
    revision_compatibility_diagnostic_with_span(code, message, subject, None)
}

fn revision_compatibility_diagnostic_with_span(
    code: &str,
    message: String,
    subject: Option<&str>,
    source_span_json: Option<String>,
) -> RevisionCompatibilityDiagnostic {
    RevisionCompatibilityDiagnostic {
        code: code.to_owned(),
        message,
        subject: subject.map(str::to_owned),
        source_span_json,
    }
}

fn add_instance_revision_diagnostics(
    context: &RevisionInstanceContext,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    if matches!(
        context.status.as_str(),
        "completed" | "failed" | "cancelled"
    ) {
        diagnostics.push(revision_compatibility_diagnostic(
            "revision.terminal_instance",
            format!(
                "instance is {}; revisions require a non-terminal instance",
                context.status
            ),
            None,
        ));
    }
}

fn contracts_by_name(summary: &Value, kind: &str) -> BTreeMap<String, ContractSummary> {
    summary
        .get("workflow_contracts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|contract| contract.get("kind").and_then(Value::as_str) == Some(kind))
        .filter_map(|contract| {
            Some((
                contract.get("name")?.as_str()?.to_owned(),
                ContractSummary {
                    ty: contract.get("type")?.as_str()?.to_owned(),
                    source_span_json: summary_source_span_json(contract),
                },
            ))
        })
        .collect()
}

fn compare_contracts(
    kind: &str,
    reject_candidate_additions: bool,
    active: &Value,
    candidate: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    let active_contracts = contracts_by_name(active, kind);
    let candidate_contracts = contracts_by_name(candidate, kind);
    for (name, active_ty) in &active_contracts {
        match candidate_contracts.get(name) {
            Some(candidate_ty) if candidate_ty.ty == active_ty.ty => {}
            Some(candidate_ty) => diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.contract_changed",
                format!(
                    "{kind} contract `{name}` changed from `{}` to `{}`",
                    active_ty.ty, candidate_ty.ty
                ),
                Some(name.as_str()),
                candidate_ty.source_span_json.clone(),
            )),
            None => diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.contract_removed",
                format!("{kind} contract `{name}` is missing from the candidate version"),
                Some(name.as_str()),
                active_ty.source_span_json.clone(),
            )),
        }
    }
    if reject_candidate_additions {
        for (name, candidate_ty) in candidate_contracts {
            if !active_contracts.contains_key(&name) {
                diagnostics.push(revision_compatibility_diagnostic_with_span(
                    "revision.input_contract_added",
                    format!(
                        "candidate adds input contract `{name}` with type `{}` to an already-started instance",
                        candidate_ty.ty
                    ),
                    Some(name.as_str()),
                    candidate_ty.source_span_json,
                ));
            }
        }
    }
}

fn compare_revision_summaries(
    active: &Value,
    candidate: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    let active_workflow = active.get("workflow").and_then(Value::as_str);
    let candidate_workflow = candidate.get("workflow").and_then(Value::as_str);
    match (active_workflow, candidate_workflow) {
        (Some(active_workflow), Some(candidate_workflow))
            if active_workflow != candidate_workflow =>
        {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.root_workflow_changed",
                format!(
                    "candidate root workflow `{candidate_workflow}` does not match active root `{active_workflow}`"
                ),
                Some(candidate_workflow),
            ));
        }
        (None, _) => diagnostics.push(revision_compatibility_diagnostic(
            "revision.active_analysis_missing",
            "active version does not include revision analysis metadata".to_owned(),
            None,
        )),
        (_, None) => diagnostics.push(revision_compatibility_diagnostic(
            "revision.candidate_analysis_missing",
            "candidate version does not include revision analysis metadata".to_owned(),
            None,
        )),
        _ => {}
    }
    compare_contracts("input", true, active, candidate, diagnostics);
    compare_contracts("output", false, active, candidate, diagnostics);
    compare_contracts("failure", false, active, candidate, diagnostics);
}

fn schemas_by_name(summary: &Value) -> BTreeMap<String, Value> {
    summary
        .get("schemas")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|schema| Some((schema.get("name")?.as_str()?.to_owned(), schema.clone())))
        .collect()
}

fn summary_source_span_json(summary: &Value) -> Option<String> {
    summary.get("source_span").map(Value::to_string)
}

fn fact_schema_name<'a>(
    fact_name: &'a str,
    schema_id: Option<&'a str>,
    active_schemas: &BTreeMap<String, Value>,
    candidate_schemas: &BTreeMap<String, Value>,
) -> Option<&'a str> {
    if let Some(schema_id) = schema_id {
        if active_schemas.contains_key(schema_id) || candidate_schemas.contains_key(schema_id) {
            return Some(schema_id);
        }
    }
    if active_schemas.contains_key(fact_name) || candidate_schemas.contains_key(fact_name) {
        return Some(fact_name);
    }
    None
}

fn is_optional_signature(signature: &str) -> bool {
    signature_envelope(signature, "optional").is_some()
}

fn signature_envelope<'a>(signature: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}<");
    signature
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix('>'))
}

fn split_top_level(input: &str, separator: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut index = 0usize;
    while index < input.len() {
        let rest = &input[index..];
        if depth == 0 && rest.starts_with(separator) {
            parts.push(input[start..index].trim().to_owned());
            index += separator.len();
            start = index;
            continue;
        }
        if let Some(ch) = rest.chars().next() {
            match ch {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            index += ch.len_utf8();
        } else {
            break;
        }
    }
    parts.push(input[start..].trim().to_owned());
    parts.retain(|part| !part.is_empty());
    parts
}

fn validate_value_against_object_signature(
    value: &Value,
    inner: &str,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    let Some(fields) = inner
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        errors.push(format!("{path} uses malformed object type"));
        return;
    };
    let fields = split_top_level(fields, ", ")
        .into_iter()
        .filter_map(|field| {
            let (name, signature) = field.split_once(' ')?;
            Some(serde_json::json!({ "name": name, "type": signature }))
        })
        .collect::<Vec<_>>();
    validate_value_against_fields(value, Some(&fields), schemas, path, errors, depth + 1);
}

fn validate_value_against_type_signature(
    value: &Value,
    signature: &str,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{path} exceeded schema recursion limit"));
        return;
    }
    match signature {
        "string" | "duration" | "time" | "image" | "audio" | "pdf" | "video" => {
            if !value.is_string() {
                errors.push(format!("{path} must be {signature}"));
            }
        }
        "int" => {
            if value.as_i64().is_none() {
                errors.push(format!("{path} must be int"));
            }
        }
        "float" => {
            if value.as_f64().is_none() {
                errors.push(format!("{path} must be float"));
            }
        }
        "bool" => {
            if !value.is_boolean() {
                errors.push(format!("{path} must be bool"));
            }
        }
        "null" => {
            if !value.is_null() {
                errors.push(format!("{path} must be null"));
            }
        }
        _ => {
            if let Some(expected) = signature_envelope(signature, "literal") {
                let expected = serde_json::from_str::<String>(expected)
                    .unwrap_or_else(|_| expected.to_owned());
                if value.as_str() != Some(expected.as_str()) {
                    errors.push(format!("{path} must be literal {expected:?}"));
                }
            } else if let Some(schema_name) = signature_envelope(signature, "ref") {
                match schemas.get(schema_name) {
                    Some(schema) => validate_fact_value_against_schema(
                        value,
                        schema,
                        schemas,
                        path,
                        errors,
                        depth + 1,
                    ),
                    None => errors.push(format!(
                        "{path} references schema `{schema_name}` missing from candidate"
                    )),
                }
            } else if let Some(inner) = signature_envelope(signature, "optional") {
                if !value.is_null() {
                    validate_value_against_type_signature(
                        value,
                        inner,
                        schemas,
                        path,
                        errors,
                        depth + 1,
                    );
                }
            } else if let Some(inner) = signature_envelope(signature, "array") {
                match value.as_array() {
                    Some(items) => {
                        for (index, item) in items.iter().enumerate() {
                            validate_value_against_type_signature(
                                item,
                                inner,
                                schemas,
                                &format!("{path}[{index}]"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                    None => errors.push(format!("{path} must be an array")),
                }
            } else if let Some(inner) = signature_envelope(signature, "map") {
                match value.as_object() {
                    Some(map) => {
                        for (key, item) in map {
                            validate_value_against_type_signature(
                                item,
                                inner,
                                schemas,
                                &format!("{path}.{key}"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                    None => errors.push(format!("{path} must be an object map")),
                }
            } else if let Some(inner) = signature_envelope(signature, "union") {
                let variants = split_top_level(inner, " | ");
                if !variants.iter().any(|variant| {
                    let mut candidate_errors = Vec::new();
                    validate_value_against_type_signature(
                        value,
                        variant,
                        schemas,
                        path,
                        &mut candidate_errors,
                        depth + 1,
                    );
                    candidate_errors.is_empty()
                }) {
                    errors.push(format!(
                        "{path} must match one of: {}",
                        variants.join(" | ")
                    ));
                }
            } else if let Some(inner) = signature_envelope(signature, "object") {
                validate_value_against_object_signature(value, inner, schemas, path, errors, depth);
            } else if let Some(inner) = signature_envelope(signature, "agentref") {
                let agents = split_top_level(inner, " | ");
                match value.as_str() {
                    Some(agent) if agents.iter().any(|candidate| candidate == agent) => {}
                    Some(_) => errors.push(format!(
                        "{path} must name one of these agents: {}",
                        agents.join(", ")
                    )),
                    None => errors.push(format!("{path} must be an agent name string")),
                }
            } else {
                errors.push(format!("{path} uses unsupported type `{signature}`"));
            }
        }
    }
}

fn validate_value_against_fields(
    value: &Value,
    fields: Option<&Vec<Value>>,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    let Some(object) = value.as_object() else {
        errors.push(format!("{path} must be an object"));
        return;
    };
    let fields = fields.map(Vec::as_slice).unwrap_or(&[]);
    let declared = fields
        .iter()
        .filter_map(|field| Some((field.get("name")?.as_str()?, field.get("type")?.as_str()?)))
        .collect::<BTreeMap<_, _>>();
    for key in object.keys() {
        if !declared.contains_key(key.as_str()) {
            errors.push(format!("{path}.{key} is not declared by candidate"));
        }
    }
    for (name, signature) in declared {
        let field_path = format!("{path}.{name}");
        match object.get(name) {
            Some(value) => {
                validate_value_against_type_signature(
                    value,
                    signature,
                    schemas,
                    &field_path,
                    errors,
                    depth + 1,
                );
            }
            None if is_optional_signature(signature) => {}
            None => errors.push(format!("{field_path} is required by candidate")),
        }
    }
}

fn validate_fact_value_against_schema(
    value: &Value,
    schema: &Value,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{path} exceeded schema recursion limit"));
        return;
    }
    match schema.get("kind").and_then(Value::as_str) {
        Some("class") => validate_value_against_fields(
            value,
            schema.get("fields").and_then(Value::as_array),
            schemas,
            path,
            errors,
            depth,
        ),
        Some("enum") => {
            let variants = schema
                .get("variants")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            match value.as_str() {
                Some(variant) if variants.contains(&variant) => {}
                Some(variant) => errors.push(format!(
                    "{path} has enum variant `{variant}` not declared by candidate"
                )),
                None => errors.push(format!("{path} must be a string enum variant")),
            }
        }
        Some(kind) => errors.push(format!("{path} uses unsupported schema kind `{kind}`")),
        None => errors.push(format!("{path} uses schema without a kind")),
    }
}

/// The active revision context (program + version + status) for an instance,
/// mirroring `revision_instance_context_on`.
fn do_revision_instance_context<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
) -> StoreResult<RevisionInstanceContext> {
    let rows = sql
        .query(
            "SELECT instances.program_id, programs.name, instances.version_id, instances.status \
             FROM instances JOIN programs ON programs.program_id = instances.program_id \
             WHERE instances.instance_id = ?1",
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    let row = rows
        .first()
        .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
    Ok(RevisionInstanceContext {
        program_id: as_text(&row[0]),
        program_name: as_text(&row[1]),
        active_version_id: as_text(&row[2]),
        status: as_text(&row[3]),
    })
}

/// `(program_id, analysis_summary)` for a version, mirroring
/// `program_version_analysis_on`.
fn do_program_version_analysis<Sql: DoSql>(
    sql: &Sql,
    version_id: &str,
) -> StoreResult<(String, Value)> {
    let rows = sql
        .query(
            "SELECT program_id, analysis_summary FROM program_versions WHERE version_id = ?1",
            &[text(version_id)],
        )
        .map_err(sql_err)?;
    let row = rows
        .first()
        .ok_or_else(|| StoreError::Conflict("program version does not exist".to_owned()))?;
    Ok((
        as_text(&row[0]),
        serde_json::from_str::<Value>(&as_text(&row[1]))?,
    ))
}

/// Adds diagnostics for active facts that no longer typecheck against the
/// candidate's schemas, mirroring `add_active_fact_schema_diagnostics`.
fn do_add_active_fact_schema_diagnostics<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    active_summary: &Value,
    candidate_summary: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) -> StoreResult<()> {
    let active_schemas = schemas_by_name(active_summary);
    let candidate_schemas = schemas_by_name(candidate_summary);
    if active_schemas.is_empty() && candidate_schemas.is_empty() {
        return Ok(());
    }
    let rows = sql
        .query(
            "SELECT fact_id, name, schema_id, value_json FROM facts \
             WHERE instance_id = ?1 AND consumed_at IS NULL ORDER BY fact_id",
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    for row in &rows {
        let fact_id = as_text(&row[0]);
        let name = as_text(&row[1]);
        let schema_id = as_opt_text(&row[2]);
        let value_json = as_text(&row[3]);
        let Some(schema_name) = fact_schema_name(
            &name,
            schema_id.as_deref(),
            &active_schemas,
            &candidate_schemas,
        ) else {
            continue;
        };
        let Some(candidate_schema) = candidate_schemas.get(schema_name) else {
            let source_span_json = active_schemas
                .get(schema_name)
                .and_then(summary_source_span_json);
            diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.active_fact_schema_removed",
                format!("active fact `{fact_id}` uses schema `{schema_name}` missing from candidate version"),
                Some(schema_name),
                source_span_json,
            ));
            continue;
        };
        let value = serde_json::from_str::<Value>(&value_json)?;
        let mut errors = Vec::new();
        validate_fact_value_against_schema(
            &value,
            candidate_schema,
            &candidate_schemas,
            "$",
            &mut errors,
            0,
        );
        if !errors.is_empty() {
            diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.active_fact_incompatible",
                format!(
                    "active fact `{fact_id}` no longer typechecks as `{schema_name}`: {}",
                    errors.join("; ")
                ),
                Some(schema_name),
                summary_source_span_json(candidate_schema),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy / capacity block engine — the capability + profile enforcement the
// scheduler applies when deciding whether an effect is claimable. Ported from the
// native store's policy helpers; the pure-JSON helpers are backend-agnostic, the
// SQL ones run over `DoSql`.
// ---------------------------------------------------------------------------

/// The scheduling-relevant projection of an effect used by the policy engine.
struct PolicyEffect {
    kind: String,
    target: Option<String>,
    status: String,
    required_capabilities_json: String,
    profile: Option<String>,
    program_id: String,
    declared_profiles_json: String,
}

/// A scheduling block: the `blocked_by_*` status the effect should take and why
/// (`start_run` records both; `claimable_effects` only checks presence).
struct PolicyBlock {
    status: &'static str,
    reason: String,
}

fn capability_allowed(allowed: &[String], capability: &str) -> bool {
    allowed.iter().any(|item| item == "*" || item == capability)
}

fn capabilities_value(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn capacity_value(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_u64()
            .and_then(|capacity| i64::try_from(capacity).ok())
    })
}

fn agent_profile_in_value(value: &Value, agent: &str) -> Option<Option<String>> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_profile_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(entry) = object.get(agent) {
                return Some(
                    entry
                        .get("profile")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                );
            }
            if let Some(profile) = object
                .get("agents")
                .and_then(|agents| agent_profile_in_value(agents, agent))
            {
                return Some(profile);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                Some(
                    object
                        .get("profile")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

fn agent_capabilities_in_value(value: &Value, agent: &str) -> Option<BTreeSet<String>> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_capabilities_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(entry) = object.get(agent) {
                return Some(capabilities_value(entry.get("capabilities")?));
            }
            if let Some(capabilities) = object
                .get("agents")
                .and_then(|agents| agent_capabilities_in_value(agents, agent))
            {
                return Some(capabilities);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                object.get("capabilities").map(capabilities_value)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn agent_capacity_in_value(value: &Value, agent: &str) -> Option<i64> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_capacity_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(capacity) = object.get(agent).and_then(capacity_value) {
                return Some(capacity);
            }
            if let Some(capacity) = object
                .get(agent)
                .and_then(|entry| entry.get("capacity"))
                .and_then(capacity_value)
            {
                return Some(capacity);
            }
            if let Some(capacity) = object
                .get("agents")
                .and_then(|agents| agent_capacity_in_value(agents, agent))
            {
                return Some(capacity);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                object.get("capacity").and_then(capacity_value)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn declared_agent_profile(
    declared_profiles_json: &str,
    agent: &str,
) -> StoreResult<Option<Option<String>>> {
    Ok(agent_profile_in_value(
        &serde_json::from_str::<Value>(declared_profiles_json)?,
        agent,
    ))
}

fn declared_agents_present(declared_profiles_json: &str) -> StoreResult<bool> {
    let parsed = serde_json::from_str::<Value>(declared_profiles_json)?;
    Ok(match &parsed {
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => {
            object
                .get("agents")
                .and_then(Value::as_array)
                .is_some_and(|agents| !agents.is_empty())
                || object.iter().any(|(key, value)| {
                    if matches!(key.as_str(), "harnesses" | "workflow" | "schemas") {
                        return false;
                    }
                    value.as_object().is_some_and(|entry| {
                        entry.contains_key("profile")
                            || entry.contains_key("capacity")
                            || entry.contains_key("capabilities")
                            || entry.contains_key("harness")
                            || entry.contains_key("provider")
                    })
                })
        }
        _ => false,
    })
}

fn declared_agent_capabilities(
    declared_profiles_json: &str,
    agent: &str,
) -> StoreResult<BTreeSet<String>> {
    Ok(agent_capabilities_in_value(
        &serde_json::from_str::<Value>(declared_profiles_json)?,
        agent,
    )
    .unwrap_or_default())
}

fn declared_agent_capacity(declared_profiles_json: &str, agent: &str) -> StoreResult<Option<i64>> {
    Ok(agent_capacity_in_value(
        &serde_json::from_str::<Value>(declared_profiles_json)?,
        agent,
    ))
}

fn explicit_required_capabilities(effect: &PolicyEffect) -> StoreResult<Vec<String>> {
    let parsed = serde_json::from_str::<Value>(&effect.required_capabilities_json)?;
    let mut capabilities = parsed
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    capabilities.sort();
    capabilities.dedup();
    Ok(capabilities)
}

fn required_capabilities(effect: &PolicyEffect) -> StoreResult<Vec<String>> {
    let mut capabilities = explicit_required_capabilities(effect)?;
    if capabilities.is_empty() {
        capabilities.push(effect.kind.clone());
    }
    capabilities.sort();
    capabilities.dedup();
    Ok(capabilities)
}

fn do_effect_provider_exists<Sql: DoSql>(sql: &Sql, effect_kind: &str) -> StoreResult<bool> {
    Ok(!sql
        .query(
            "SELECT 1 FROM effect_providers WHERE effect_kind = ?1 LIMIT 1",
            &[text(effect_kind)],
        )
        .map_err(sql_err)?
        .is_empty())
}

fn do_capability_schema_exists<Sql: DoSql>(sql: &Sql, capability: &str) -> StoreResult<bool> {
    Ok(!sql
        .query(
            "SELECT 1 FROM capability_schemas WHERE capability = ?1 LIMIT 1",
            &[text(capability)],
        )
        .map_err(sql_err)?
        .is_empty())
}

fn do_capability_bound<Sql: DoSql>(
    sql: &Sql,
    program_id: &str,
    capability: &str,
) -> StoreResult<bool> {
    Ok(!sql
        .query(
            "SELECT 1 FROM capability_bindings WHERE capability = ?1 \
             AND (program_id = ?2 OR program_id IS NULL) LIMIT 1",
            &[text(capability), text(program_id)],
        )
        .map_err(sql_err)?
        .is_empty())
}

/// `(enforcement_mode, allowed_capabilities)` for a registered profile, mirroring
/// the native `profile_policy`.
fn do_profile_policy<Sql: DoSql>(
    sql: &Sql,
    profile: &str,
) -> StoreResult<Option<(String, Vec<String>)>> {
    let rows = sql
        .query(
            "SELECT enforcement_mode, allowed_capabilities FROM profiles WHERE name = ?1",
            &[text(profile)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let allowed = serde_json::from_str::<Value>(&as_text(&row[1]))?
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Some((as_text(&row[0]), allowed)))
}

/// Agent-declaration policy for `agent.tell` effects (pure — reads the declared
/// profiles JSON). Mirrors `agent_target_policy_block`.
fn agent_target_policy_block(effect: &PolicyEffect) -> StoreResult<Option<PolicyBlock>> {
    if effect.kind != "agent.tell" {
        return Ok(None);
    }
    let Some(target) = effect.target.as_deref() else {
        return Ok(None);
    };
    if !declared_agents_present(&effect.declared_profiles_json)? {
        return Ok(None);
    }
    let Some(declared_profile) = declared_agent_profile(&effect.declared_profiles_json, target)?
    else {
        return Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!("agent `{target}` is not declared by the program"),
        }));
    };
    match (effect.profile.as_deref(), declared_profile.as_deref()) {
        (Some(actual), Some(expected)) if actual != expected => Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!(
                "agent `{target}` uses profile `{actual}`, expected declared profile `{expected}`"
            ),
        })),
        (None, Some(expected)) => Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!("agent `{target}` requires declared profile `{expected}`"),
        })),
        _ => {
            let declared_capabilities =
                declared_agent_capabilities(&effect.declared_profiles_json, target)?;
            for capability in explicit_required_capabilities(effect)? {
                if !declared_capabilities.contains(&capability) {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_capability",
                        reason: format!(
                            "agent `{target}` does not declare required capability `{capability}`"
                        ),
                    }));
                }
            }
            Ok(None)
        }
    }
}

fn do_policy_block_for_capabilities<Sql: DoSql>(
    sql: &Sql,
    effect: &PolicyEffect,
    capabilities: &[String],
) -> StoreResult<Option<PolicyBlock>> {
    for capability in capabilities {
        if !do_capability_schema_exists(sql, capability)? {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_capability",
                reason: format!("capability `{capability}` is not registered"),
            }));
        }
        if !do_capability_bound(sql, &effect.program_id, capability)? {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_capability",
                reason: format!(
                    "capability `{capability}` is not bound for program {}",
                    effect.program_id
                ),
            }));
        }
    }
    if let Some(profile) = &effect.profile {
        let Some((enforcement_mode, allowed_capabilities)) = do_profile_policy(sql, profile)?
        else {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_profile",
                reason: format!("profile `{profile}` is not registered"),
            }));
        };
        if enforcement_mode != "audit" {
            for capability in capabilities {
                if !capability_allowed(&allowed_capabilities, capability) {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_profile",
                        reason: format!(
                            "profile `{profile}` does not allow capability `{capability}`"
                        ),
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// Whether a queued effect is blocked by capability/profile policy. Mirrors
/// `policy_block_on`.
/// Persist a policy block observed by the claim-list filter (parity with the
/// native `persist_policy_block_on`): flip the effect to the block's status
/// with its reason and append an `effect.blocked` event, idempotent per
/// (effect, reason). Recovery is automatic — `do_policy_block` re-evaluates
/// persisted blocks each pass.
fn do_persist_policy_block<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
    block: &PolicyBlock,
) -> StoreResult<()> {
    let changed = sql
        .execute(
            "UPDATE effects SET status = ?1, policy_block_reason = ?2, \
             updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?3 AND effect_id = ?4 \
             AND (status != ?1 OR policy_block_reason IS NOT ?2) \
             AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')",
            &[
                text(block.status),
                text(&block.reason),
                text(instance_id),
                text(effect_id),
            ],
        )
        .map_err(sql_err)?;
    if changed == 1 {
        let payload = serde_json::json!({
            "effect_id": effect_id,
            "status": block.status,
            "reason": block.reason,
        })
        .to_string();
        do_append_event_idempotent(
            sql,
            NewEvent {
                instance_id,
                event_type: "effect.blocked",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key: Some(&format!("policy-block:{effect_id}:{}", block.reason)),
            },
        )?;
    }
    Ok(())
}

fn do_policy_block<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Option<PolicyBlock>> {
    let rows = sql
        .query(
            "SELECT effects.kind, effects.target, effects.status, effects.required_capabilities, \
             effects.profile, COALESCE(effect_versions.program_id, instances.program_id), \
             COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles) \
             FROM effects JOIN instances ON instances.instance_id = effects.instance_id \
             JOIN program_versions AS active_versions \
             ON active_versions.version_id = instances.version_id \
             LEFT JOIN program_versions AS effect_versions \
             ON effect_versions.version_id = effects.program_version_id \
             WHERE effects.instance_id = ?1 AND effects.effect_id = ?2",
            &[text(instance_id), text(effect_id)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let effect = PolicyEffect {
        kind: as_text(&row[0]),
        target: as_opt_text(&row[1]),
        status: as_text(&row[2]),
        required_capabilities_json: as_text(&row[3]),
        profile: as_opt_text(&row[4]),
        program_id: as_text(&row[5]),
        declared_profiles_json: as_text(&row[6]),
    };
    // A persisted policy block is re-evaluated here every pass — that is what
    // makes it RECOVERABLE once the missing profile/capability is registered
    // (parity with native `policy_block_on`).
    if !matches!(
        effect.status.as_str(),
        "queued"
            | "blocked_by_dependency"
            | "blocked_by_capacity"
            | "blocked_by_capability"
            | "blocked_by_profile"
    ) {
        return Ok(None);
    }
    if let Some(block) = agent_target_policy_block(&effect)? {
        return Ok(Some(block));
    }
    // Timers are resolved by the runtime itself on worker passes: no provider,
    // capability, or profile applies. This is the ONLY runtime-resolved
    // exemption, matching the native gate (store/lib.rs `policy_block_on`).
    //
    // Coordination (`lease.*`/`ledger.*`/`counter.*`), file (`file.*`), tracker
    // (`tracker.*`), and ingress (`signal.emit`) kinds are NO LONGER exempt:
    // the DO-plane package bootstrap (do_packages::register_embedded_std_packages,
    // called at DurableInstance::create/attach) seeds the same
    // capability/provider/binding rows the native store seeds at init, so the
    // admission gate is REAL here too — an unbound kind blocks as
    // blocked_by_capability, parity with native (the DO tracker's "DO-plane
    // package bootstrap" row, spec/durable-object-runtime-tracker.md).
    if effect.kind == "timer.wait" {
        return Ok(None);
    }
    if effect.kind == "exec.command" {
        // Script hard-off Layer 2 (spec/std-script.md "Hard-off semantics"),
        // mirroring `policy_block_on`: EVERY exec.command effect requires a
        // bound `script.*` capability — `script.<name>` for the capability
        // form (carried from lowering), `script.raw` for the raw form (which
        // carries none). Derived at the admission gate so a forged effect row
        // that strips its requirements gains nothing.
        let mut capabilities = explicit_required_capabilities(&effect)?;
        if !capabilities
            .iter()
            .any(|capability| capability.starts_with("script."))
        {
            capabilities.push("script.raw".to_owned());
        }
        let block = do_policy_block_for_capabilities(sql, &effect, &capabilities)?;
        // A script-capability block IS the "scripts are disabled" state:
        // surface the hard-off diagnostic id with the blocked reason.
        return Ok(block.map(|block| match block.status {
            "blocked_by_capability" => PolicyBlock {
                status: block.status,
                reason: format!("security.script_disabled: {}", block.reason),
            },
            _ => block,
        }));
    }
    if effect.kind == "capability.call" {
        let mut capabilities = explicit_required_capabilities(&effect)?;
        if capabilities.is_empty() {
            match effect.target.as_deref().filter(|target| !target.is_empty()) {
                Some(target) => capabilities.push(target.to_owned()),
                None => {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_capability",
                        reason: "capability.call effect has no target capability requirement"
                            .to_owned(),
                    }))
                }
            }
        }
        return do_policy_block_for_capabilities(sql, &effect, &capabilities);
    }
    let capabilities = required_capabilities(&effect)?;
    if !do_effect_provider_exists(sql, &effect.kind)? {
        return Ok(Some(PolicyBlock {
            status: "blocked_by_capability",
            reason: format!("no effect provider is registered for `{}`", effect.kind),
        }));
    }
    do_policy_block_for_capabilities(sql, &effect, &capabilities)
}

/// Whether an `agent.tell` effect is blocked by its agent's running-capacity cap.
/// Mirrors `capacity_block_on`.
fn do_capacity_block<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Option<String>> {
    let rows = sql
        .query(
            "SELECT effects.kind, effects.target, \
             COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles) \
             FROM effects JOIN instances ON instances.instance_id = effects.instance_id \
             JOIN program_versions AS active_versions \
             ON active_versions.version_id = instances.version_id \
             LEFT JOIN program_versions AS effect_versions \
             ON effect_versions.version_id = effects.program_version_id \
             WHERE effects.instance_id = ?1 AND effects.effect_id = ?2",
            &[text(instance_id), text(effect_id)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let kind = as_text(&row[0]);
    if kind != "agent.tell" {
        return Ok(None);
    }
    let Some(agent) = as_opt_text(&row[1]) else {
        return Ok(None);
    };
    let Some(capacity) = declared_agent_capacity(&as_text(&row[2]), &agent)? else {
        return Ok(None);
    };
    let running_rows = sql
        .query(
            "SELECT COUNT(*) FROM effects WHERE instance_id = ?1 AND kind = 'agent.tell' \
             AND target = ?2 AND status = 'running'",
            &[text(instance_id), text(&agent)],
        )
        .map_err(sql_err)?;
    let running = running_rows.first().map(|r| as_i64(&r[0])).unwrap_or(0);
    if running >= capacity {
        Ok(Some(format!(
            "agent `{agent}` capacity exhausted ({running}/{capacity} running)"
        )))
    } else {
        Ok(None)
    }
}

/// The shared 19-column workflow-invocation projection (parent/child active
/// versions joined, status folded to the parent effect's terminal). Callers
/// append their own `WHERE ... ORDER BY ...` clause. Mirrors the native SQL.
const WORKFLOW_INVOCATION_SELECT: &str = "SELECT invocation_id, parent_instance_id, \
     parent_effect_id, parent_program_version_id, parent_revision_epoch, \
     parent_instance.version_id, parent_instance.revision_epoch, child_instance_id, \
     child_program_version_id, child_revision_epoch, child_instance.version_id, \
     child_instance.revision_epoch, workflow_invocations.target_workflow, \
     workflow_invocations.input_json, \
     CASE WHEN parent_effect.status IN ('completed', 'failed', 'timed_out', 'cancelled') \
     THEN parent_effect.status ELSE workflow_invocations.status END, \
     workflow_invocations.terminal_event_id, workflow_invocations.source_span_json, \
     workflow_invocations.created_at, \
     COALESCE(workflow_invocations.updated_at, workflow_invocations.created_at) \
     FROM workflow_invocations \
     LEFT JOIN instances AS parent_instance \
     ON parent_instance.instance_id = workflow_invocations.parent_instance_id \
     LEFT JOIN instances AS child_instance \
     ON child_instance.instance_id = workflow_invocations.child_instance_id \
     LEFT JOIN effects AS parent_effect \
     ON parent_effect.instance_id = workflow_invocations.parent_instance_id \
     AND parent_effect.effect_id = workflow_invocations.parent_effect_id ";

impl<Sql: DoSql> DoSqliteStore<Sql> {
    /// RC-2 Delta A (DO mirror): bounded projection replay. Reconstructs the
    /// instance's projection tables AS OF event `up_to_sequence` — every
    /// persisted event with `sequence <= up_to_sequence` is applied, none
    /// after. `N` is INCLUSIVE. When `up_to_sequence` is `None` this is the
    /// unbounded full rebuild (the `RuntimeStore::rebuild_projections` default,
    /// byte-identical to before). `up_to_sequence` is the single cut coordinate
    /// shared with the transcript plane and the file manifest.
    pub fn rebuild_projections_to(
        &mut self,
        instance_id: &str,
        up_to_sequence: i64,
    ) -> StoreResult<()> {
        self.rebuild_projections_impl(instance_id, Some(up_to_sequence))
    }

    fn rebuild_projections_impl(
        &mut self,
        instance_id: &str,
        up_to_sequence: Option<i64>,
    ) -> StoreResult<()> {
        // Detach artifacts from the runs we're about to delete, then re-link the
        // surviving ones after replay.
        let artifact_rows = self
            .sql
            .query(
                "SELECT artifact_id, run_id FROM artifacts \
                 WHERE run_id IN (SELECT run_id FROM runs WHERE instance_id = ?1) \
                 ORDER BY artifact_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        let artifact_run_links: Vec<(String, String)> = artifact_rows
            .iter()
            .map(|r| (as_text(&r[0]), as_text(&r[1])))
            .collect();
        for (artifact_id, _) in &artifact_run_links {
            self.sql
                .execute(
                    "UPDATE artifacts SET run_id = NULL WHERE artifact_id = ?1",
                    &[text(artifact_id)],
                )
                .map_err(sql_err)?;
        }
        for table in [
            "effect_cancellation_requests",
            "leases",
            "runs",
            "instance_revisions",
            "effect_dependencies",
            "effects",
            "facts",
        ] {
            self.sql
                .execute(
                    &format!("DELETE FROM {table} WHERE instance_id = ?1"),
                    &[text(instance_id)],
                )
                .map_err(sql_err)?;
        }

        // RC-2 Delta A: when a bound is present, cut the replayed event set at
        // `sequence <= N` (INCLUSIVE). `N` is an i64 so interpolation is
        // injection-safe; when unbounded the clause is empty, leaving the
        // full-replay query semantically identical to before.
        let bound_clause = match up_to_sequence {
            Some(n) => format!(" AND sequence <= {n}"),
            None => String::new(),
        };
        // RC-4b: fetch `context.restored` markers alongside state events (and
        // select `sequence`) so the restore-marker replay fold below can honor
        // them (models/maude/restore-replay.maude).
        let events = self
            .sql
            .query(
                &format!(
                    "SELECT event_id, event_type, payload_json, idempotency_key, causation_id, source, sequence, format_version \
                     FROM events WHERE instance_id = ?1 AND event_type IN ( \
                     'rule.committed', 'fact.derived', 'workflow.completed', 'workflow.failed', \
                     'instance.transitioned', 'workflow.revision_activated', 'effect.run_started', \
                     'effect.terminal', 'effect.cancelled', 'effect.cancellation_requested', \
                     'lease.expired', 'context.restored'){bound_clause} ORDER BY sequence"
                ),
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        // DR-0054 Phase B: fail the fold closed on an event row stamped with a
        // format this build does not understand (native rebuild parity). Legacy
        // NULL rows read as version 1 and pass.
        for row in &events {
            if let Some(version) = as_opt_i64(&row[7]) {
                if version > whipplescript_store::SUPPORTED_EVENT_FORMAT_VERSION {
                    return Err(StoreError::UnsupportedVersion {
                        subject: format!(
                            "event `{}` (instance `{instance_id}`, sequence {})",
                            as_text(&row[0]),
                            as_i64(&row[6])
                        ),
                        found: version,
                        supported: whipplescript_store::SUPPORTED_EVENT_FORMAT_VERSION,
                    });
                }
            }
        }
        // RC-4b restore-marker fold: walk ascending; a `context.restored` marker
        // rewinds the live set to its target sequence, dropping every event a
        // later restore orphaned. With no markers present, `live` is exactly the
        // ordered state-event set, so the rebuild is byte-identical for instances
        // that were never restored.
        let mut live: Vec<usize> = Vec::new();
        for (idx, row) in events.iter().enumerate() {
            if as_text(&row[1]) == "context.restored" {
                if let Some(target) = do_restore_marker_target(&as_text(&row[2])) {
                    live.retain(|&i| as_i64(&events[i][6]) <= target);
                }
            } else {
                live.push(idx);
            }
        }
        for &idx in &live {
            let row = &events[idx];
            let event_id = as_text(&row[0]);
            let event_type = as_text(&row[1]);
            let payload_json = as_text(&row[2]);
            let idempotency_key = as_opt_text(&row[3]);
            let causation_id = as_opt_text(&row[4]);
            let source = as_text(&row[5]);
            match event_type.as_str() {
                "rule.committed" => {
                    do_replay_rule_commit(&self.sql, instance_id, &event_id, &payload_json)?
                }
                "fact.derived" => do_replay_fact_derived(
                    &self.sql,
                    instance_id,
                    &event_id,
                    &source,
                    &payload_json,
                )?,
                "workflow.completed" | "workflow.failed" => do_replay_workflow_terminal(
                    &self.sql,
                    instance_id,
                    &event_id,
                    &event_type,
                    &payload_json,
                )?,
                "instance.transitioned" => {
                    do_replay_instance_transition(&self.sql, instance_id, &event_id, &payload_json)?
                }
                "workflow.revision_activated" => do_replay_revision_activation(
                    &self.sql,
                    instance_id,
                    &event_id,
                    &payload_json,
                    idempotency_key.as_deref(),
                )?,
                "effect.run_started" => {
                    do_replay_run_started(&self.sql, instance_id, &payload_json)?
                }
                "effect.terminal" => {
                    do_replay_effect_terminal(&self.sql, instance_id, &event_id, &payload_json)?
                }
                "effect.cancelled" => {
                    do_replay_effect_cancelled(&self.sql, instance_id, &event_id, &payload_json)?
                }
                "effect.cancellation_requested" => do_replay_cancellation_request(
                    &self.sql,
                    instance_id,
                    &event_id,
                    &payload_json,
                    idempotency_key.as_deref(),
                    causation_id.as_deref(),
                )?,
                "lease.expired" => do_replay_lease_expired(&self.sql, instance_id, &payload_json)?,
                _ => {}
            }
        }

        for (artifact_id, run_id) in artifact_run_links {
            let run_exists = !self
                .sql
                .query("SELECT 1 FROM runs WHERE run_id = ?1", &[text(&run_id)])
                .map_err(sql_err)?
                .is_empty();
            if run_exists {
                self.sql
                    .execute(
                        "UPDATE artifacts SET run_id = ?1 WHERE artifact_id = ?2",
                        &[text(&run_id), text(&artifact_id)],
                    )
                    .map_err(sql_err)?;
            }
        }
        Ok(())
    }
}

#[allow(unused_variables, clippy::todo, clippy::too_many_arguments)]
impl<Sql: DoSql> RuntimeStore for DoSqliteStore<Sql> {
    fn schema_version(&self) -> StoreResult<i64> {
        let rows = self
            .sql
            .query(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .first()
            .and_then(|r| r.first())
            .map(as_i64)
            .unwrap_or(0))
    }

    fn append_event(&self, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
        do_append_event(&self.sql, event)
    }

    fn create_program_version(
        &mut self,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        self.sql
            .execute(
                "INSERT INTO programs (program_id, name) \
                 VALUES ('prg_' || lower(hex(randomblob(16))), ?1) ON CONFLICT(name) DO NOTHING",
                &[text(version.program_name)],
            )
            .map_err(sql_err)?;
        let program_rows = self
            .sql
            .query(
                "SELECT program_id FROM programs WHERE name = ?1",
                &[text(version.program_name)],
            )
            .map_err(sql_err)?;
        let program_id = program_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("program row missing after insert".to_string()))?;
        self.sql
            .execute(
                "INSERT INTO program_versions (version_id, program_id, source_hash, ir_hash, \
                 compiler_version, declared_capabilities, declared_profiles, declared_skills, \
                 declared_schemas, analysis_summary, generated_artifacts, artifact_root) VALUES \
                 ('ver_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                 ?11) ON CONFLICT(program_id, source_hash, ir_hash) DO NOTHING",
                &[
                    text(&program_id),
                    text(version.source_hash),
                    text(version.ir_hash),
                    text(version.compiler_version),
                    text(version.declared_capabilities_json),
                    text(version.declared_profiles_json),
                    text(version.declared_skills_json),
                    text(version.declared_schemas_json),
                    text(version.analysis_summary_json),
                    text(version.generated_artifacts_json),
                    opt_text(version.artifact_root),
                ],
            )
            .map_err(sql_err)?;
        let version_rows = self
            .sql
            .query(
                "SELECT version_id FROM program_versions \
                 WHERE program_id = ?1 AND source_hash = ?2 AND ir_hash = ?3",
                &[
                    text(&program_id),
                    text(version.source_hash),
                    text(version.ir_hash),
                ],
            )
            .map_err(sql_err)?;
        let version_id = version_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("program_version row missing after insert".to_string()))?;
        Ok(ProgramVersionRecord {
            program_id,
            version_id,
        })
    }

    fn reattest_instance_program(
        &mut self,
        instance_id: &str,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        // Same semantics as `SqliteStore::reattest_instance_program`: the DO's
        // single-writer serializes these statements, standing in for the
        // native transaction.
        let recorded_rows = self
            .sql
            .query(
                "SELECT instances.program_id, instances.version_id, \
                 program_versions.source_hash, program_versions.ir_hash FROM instances \
                 JOIN program_versions ON program_versions.version_id = instances.version_id \
                 WHERE instances.instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        let Some(row) = recorded_rows.first() else {
            return Err(StoreError::Conflict(format!(
                "cannot re-attest unknown instance {instance_id}"
            )));
        };
        let program_id = as_text(&row[0]);
        let from_version_id = as_text(&row[1]);
        let recorded_source = as_text(&row[2]);
        let recorded_ir = as_text(&row[3]);
        if recorded_source != version.source_hash {
            return Err(StoreError::Conflict(
                "re-attestation requires the same authored program".to_owned(),
            ));
        }
        if recorded_ir == version.ir_hash {
            return Ok(ProgramVersionRecord {
                program_id,
                version_id: from_version_id,
            });
        }
        self.sql
            .execute(
                "INSERT INTO program_versions (version_id, program_id, source_hash, ir_hash, \
                 compiler_version, declared_capabilities, declared_profiles, declared_skills, \
                 declared_schemas, analysis_summary, generated_artifacts, artifact_root) VALUES \
                 ('ver_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                 ?11) ON CONFLICT(program_id, source_hash, ir_hash) DO NOTHING",
                &[
                    text(&program_id),
                    text(version.source_hash),
                    text(version.ir_hash),
                    text(version.compiler_version),
                    text(version.declared_capabilities_json),
                    text(version.declared_profiles_json),
                    text(version.declared_skills_json),
                    text(version.declared_schemas_json),
                    text(version.analysis_summary_json),
                    text(version.generated_artifacts_json),
                    opt_text(version.artifact_root),
                ],
            )
            .map_err(sql_err)?;
        let version_rows = self
            .sql
            .query(
                "SELECT version_id FROM program_versions \
                 WHERE program_id = ?1 AND source_hash = ?2 AND ir_hash = ?3",
                &[
                    text(&program_id),
                    text(version.source_hash),
                    text(version.ir_hash),
                ],
            )
            .map_err(sql_err)?;
        let to_version_id = version_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("program_version row missing after insert".to_string()))?;
        let payload = serde_json::json!({
            "from_version_id": &from_version_id,
            "to_version_id": &to_version_id,
            "source_hash": version.source_hash,
            "from_ir_hash": &recorded_ir,
            "to_ir_hash": version.ir_hash,
            "compiler_version": version.compiler_version,
        })
        .to_string();
        let idempotency = format!("reattest:{instance_id}:{from_version_id}:{to_version_id}");
        do_append_event_idempotent(
            &self.sql,
            NewEvent {
                instance_id,
                event_type: "instance.program.reattested",
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some(&idempotency),
            },
        )?;
        self.sql
            .execute(
                "UPDATE instances SET version_id = ?1 WHERE instance_id = ?2",
                &[text(&to_version_id), text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(ProgramVersionRecord {
            program_id,
            version_id: to_version_id,
        })
    }

    fn get_program_version(&self, version_id: &str) -> StoreResult<Option<ProgramVersionView>> {
        let rows = self
            .sql
            .query(
                "SELECT program_versions.program_id, programs.name, \
                 program_versions.version_id, program_versions.source_hash, \
                 program_versions.ir_hash, program_versions.compiler_version, \
                 program_versions.analysis_summary FROM program_versions \
                 JOIN programs ON programs.program_id = program_versions.program_id \
                 WHERE program_versions.version_id = ?1",
                &[text(version_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| program_version_from_row(r)))
    }

    fn create_instance(&self, instance: NewInstance<'_>) -> StoreResult<InstanceRecord> {
        self.create_instance_with_authority(instance, NewInstanceAuthority::empty())
    }

    fn create_instance_with_authority(
        &self,
        instance: NewInstance<'_>,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<InstanceRecord> {
        let rows = self
            .sql
            .query(
                "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
                 effective_authority, status, input_json, started_at) VALUES \
                 ('ins_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, 'running', ?5, \
                 CURRENT_TIMESTAMP) RETURNING instance_id, status",
                &[
                    text(instance.program_id),
                    text(instance.version_id),
                    text(authority.workflow_principal),
                    text(authority.effective_authority_json),
                    text(instance.input_json),
                ],
            )
            .map_err(sql_err)?;
        let row = rows
            .first()
            .ok_or_else(|| sql_err("create_instance returned no row".to_string()))?;
        Ok(InstanceRecord {
            instance_id: as_text(&row[0]),
            status: as_text(&row[1]),
        })
    }

    fn list_instance_revisions(&self, instance_id: &str) -> StoreResult<Vec<WorkflowRevisionView>> {
        let rows = self
            .sql
            .query(
                "SELECT revision_id, instance_id, epoch, from_version_id, to_version_id, \
                 activated_by_event_id, activation_policy_json, cancellation_policy, status, \
                 idempotency_key, created_at, activated_at FROM instance_revisions \
                 WHERE instance_id = ?1 ORDER BY epoch",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| workflow_revision_from_row(r)).collect())
    }

    fn revision_cancellation_impact(
        &self,
        instance_id: &str,
        cancellation_policy: &str,
    ) -> StoreResult<RevisionCancellationImpact> {
        let cancellation_policy = normalize_cancellation_policy(cancellation_policy)?;
        let rows = self
            .sql
            .query(
                "SELECT version_id, revision_epoch, status FROM instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        let row = rows
            .first()
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        let active_version_id = as_text(&row[0]);
        let active_revision_epoch = as_i64(&row[1]);
        let status = as_text(&row[2]);
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(StoreError::Conflict(format!(
                "instance is {status}; revision impact requires a non-terminal instance"
            )));
        }
        let terminal_cancel_effects = if cancellation_policy == "keep" {
            Vec::new()
        } else {
            do_revision_policy_effects(&self.sql, instance_id, false)?
        };
        let request_cancel_effects = if cancellation_policy == "request_running" {
            do_revision_policy_effects(&self.sql, instance_id, true)?
        } else {
            Vec::new()
        };
        Ok(RevisionCancellationImpact {
            instance_id: instance_id.to_owned(),
            active_version_id,
            active_revision_epoch,
            cancellation_policy: cancellation_policy.to_owned(),
            terminal_cancel_effects,
            request_cancel_effects,
        })
    }

    fn analyze_revision_compatibility(
        &self,
        instance_id: &str,
        candidate_version_id: &str,
    ) -> StoreResult<RevisionCompatibilityReport> {
        let context = do_revision_instance_context(&self.sql, instance_id)?;
        let (active_program_id, active_summary) =
            do_program_version_analysis(&self.sql, &context.active_version_id)?;
        let (candidate_program_id, candidate_summary) =
            do_program_version_analysis(&self.sql, candidate_version_id)?;

        let mut diagnostics = Vec::new();
        add_instance_revision_diagnostics(&context, &mut diagnostics);
        if active_program_id != context.program_id || candidate_program_id != context.program_id {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.program_mismatch",
                "candidate version belongs to a different program".to_owned(),
                Some(candidate_version_id),
            ));
        }
        compare_revision_summaries(&active_summary, &candidate_summary, &mut diagnostics);
        do_add_active_fact_schema_diagnostics(
            &self.sql,
            instance_id,
            &active_summary,
            &candidate_summary,
            &mut diagnostics,
        )?;

        Ok(RevisionCompatibilityReport {
            instance_id: instance_id.to_owned(),
            active_version_id: context.active_version_id,
            candidate_version_id: candidate_version_id.to_owned(),
            compatible: diagnostics.is_empty(),
            diagnostics,
        })
    }

    fn analyze_revision_candidate(
        &self,
        instance_id: &str,
        candidate: RevisionCandidate<'_>,
    ) -> StoreResult<RevisionCompatibilityReport> {
        let context = do_revision_instance_context(&self.sql, instance_id)?;
        let (_active_program_id, active_summary) =
            do_program_version_analysis(&self.sql, &context.active_version_id)?;
        let candidate_summary = serde_json::from_str::<Value>(candidate.analysis_summary_json)?;

        let mut diagnostics = Vec::new();
        add_instance_revision_diagnostics(&context, &mut diagnostics);
        if candidate.program_name != context.program_name {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.program_mismatch",
                format!(
                    "candidate program `{}` does not match active program `{}`",
                    candidate.program_name, context.program_name
                ),
                Some(candidate.program_name),
            ));
        }
        compare_revision_summaries(&active_summary, &candidate_summary, &mut diagnostics);
        do_add_active_fact_schema_diagnostics(
            &self.sql,
            instance_id,
            &active_summary,
            &candidate_summary,
            &mut diagnostics,
        )?;

        Ok(RevisionCompatibilityReport {
            instance_id: instance_id.to_owned(),
            active_version_id: context.active_version_id,
            candidate_version_id: candidate.candidate_version_id.to_owned(),
            compatible: diagnostics.is_empty(),
            diagnostics,
        })
    }

    fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView> {
        let cancellation_policy = normalize_cancellation_policy(activation.cancellation_policy)?;
        let activation_policy: Value = serde_json::from_str(activation.activation_policy_json)?;

        // Idempotent replay: an existing revision with the same key + input is returned.
        if let Some(idempotency_key) = activation.idempotency_key {
            if let Some(existing) =
                do_revision_by_idempotency(&self.sql, activation.instance_id, idempotency_key)?
            {
                ensure_revision_idempotency_matches(
                    &existing,
                    &activation,
                    &activation_policy,
                    cancellation_policy,
                )?;
                return Ok(existing);
            }
        }

        let instance_rows = self
            .sql
            .query(
                "SELECT instances.program_id, programs.name, instances.version_id, \
                 instances.revision_epoch, instances.status FROM instances \
                 JOIN programs ON programs.program_id = instances.program_id \
                 WHERE instances.instance_id = ?1",
                &[text(activation.instance_id)],
            )
            .map_err(sql_err)?;
        let row = instance_rows
            .first()
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        let program_id = as_text(&row[0]);
        let program_name = as_text(&row[1]);
        let current_version_id = as_text(&row[2]);
        let current_epoch = as_i64(&row[3]);
        let status = as_text(&row[4]);
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(StoreError::Conflict(format!(
                "instance is {status}; revisions require a non-terminal instance"
            )));
        }
        if current_version_id != activation.from_version_id {
            return Err(StoreError::Conflict(format!(
                "active version is {current_version_id}; expected {}",
                activation.from_version_id
            )));
        }
        let to_rows = self
            .sql
            .query(
                "SELECT program_id FROM program_versions WHERE version_id = ?1",
                &[text(activation.to_version_id)],
            )
            .map_err(sql_err)?;
        let to_program_id = to_rows.first().map(|r| as_text(&r[0])).ok_or_else(|| {
            StoreError::Conflict("target program version does not exist".to_owned())
        })?;
        if to_program_id != program_id {
            return Err(StoreError::Conflict(
                "target version belongs to a different program".to_owned(),
            ));
        }
        // Compatibility gate.
        let (_active_program_id, active_summary) =
            do_program_version_analysis(&self.sql, &current_version_id)?;
        let (_candidate_program_id, candidate_summary) =
            do_program_version_analysis(&self.sql, activation.to_version_id)?;
        let mut compatibility_diagnostics = Vec::new();
        let context = RevisionInstanceContext {
            program_id: program_id.clone(),
            program_name,
            active_version_id: current_version_id.clone(),
            status: status.clone(),
        };
        add_instance_revision_diagnostics(&context, &mut compatibility_diagnostics);
        compare_revision_summaries(
            &active_summary,
            &candidate_summary,
            &mut compatibility_diagnostics,
        );
        do_add_active_fact_schema_diagnostics(
            &self.sql,
            activation.instance_id,
            &active_summary,
            &candidate_summary,
            &mut compatibility_diagnostics,
        )?;
        if !compatibility_diagnostics.is_empty() {
            let codes = compatibility_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(StoreError::Conflict(format!(
                "revision candidate is incompatible: {codes}"
            )));
        }

        let next_epoch = current_epoch + 1;
        let id_rows = self
            .sql
            .query(
                "SELECT ?1 || '_' || lower(hex(randomblob(16)))",
                &[text("rev")],
            )
            .map_err(sql_err)?;
        let revision_id = id_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("failed to mint revision id".to_string()))?;
        let queued_effects = do_revision_policy_effects(&self.sql, activation.instance_id, false)?;
        let running_effects = do_revision_policy_effects(&self.sql, activation.instance_id, true)?;
        let queued_effects_for_policy = if cancellation_policy == "keep" {
            Vec::new()
        } else {
            queued_effects
        };
        let running_effects_for_policy = if cancellation_policy == "request_running" {
            running_effects
        } else {
            Vec::new()
        };
        let payload = serde_json::json!({
            "revision_id": &revision_id,
            "instance_id": activation.instance_id,
            "from_version_id": activation.from_version_id,
            "to_version_id": activation.to_version_id,
            "from_epoch": current_epoch,
            "to_epoch": next_epoch,
            "activation_policy": activation_policy,
            "cancellation_policy": cancellation_policy,
            "terminal_cancel_effects": &queued_effects_for_policy,
            "request_cancel_effects": &running_effects_for_policy,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: activation.instance_id,
                event_type: "workflow.revision_activated",
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: Some(&revision_id),
                idempotency_key: activation.idempotency_key,
            },
        )?;
        self.sql
            .execute(
                "INSERT INTO instance_revisions (revision_id, instance_id, epoch, from_version_id, \
                 to_version_id, activated_by_event_id, activation_policy_json, cancellation_policy, \
                 status, idempotency_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)",
                &[
                    text(&revision_id),
                    text(activation.instance_id),
                    int(next_epoch),
                    text(activation.from_version_id),
                    text(activation.to_version_id),
                    text(&event.event_id),
                    text(activation.activation_policy_json),
                    text(cancellation_policy),
                    opt_text(activation.idempotency_key),
                ],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "UPDATE instances SET version_id = ?1, revision_epoch = ?2, last_event_id = ?3, \
                 updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?4",
                &[
                    text(activation.to_version_id),
                    int(next_epoch),
                    text(&event.event_id),
                    text(activation.instance_id),
                ],
            )
            .map_err(sql_err)?;

        for effect_id in &queued_effects_for_policy {
            let cancel_payload = serde_json::json!({
                "effect_id": effect_id,
                "status": "cancelled",
                "revision_id": &revision_id,
                "reason": "workflow revision",
            })
            .to_string();
            let cancel_idempotency_key = format!("revision-cancel:{revision_id}:{effect_id}");
            let cancel_event = do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: activation.instance_id,
                    event_type: "effect.terminal",
                    payload_json: &cancel_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: Some(&revision_id),
                    idempotency_key: Some(&cancel_idempotency_key),
                },
            )?;
            self.sql
                .execute(
                    "UPDATE effects SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP \
                     WHERE instance_id = ?1 AND effect_id = ?2 AND status IN ('queued', 'blocked', \
                     'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', \
                     'blocked_by_profile')",
                    &[text(activation.instance_id), text(effect_id)],
                )
                .map_err(sql_err)?;
            do_mark_cancellation_requests_terminal(
                &self.sql,
                activation.instance_id,
                effect_id,
                &cancel_event.event_id,
            )?;
        }
        if !queued_effects_for_policy.is_empty() {
            self.satisfy_dependencies(activation.instance_id)?;
        }
        let mut cancellation_request_ids = Vec::new();
        for effect_id in &running_effects_for_policy {
            let request_idempotency_key =
                format!("revision-request-cancel:{revision_id}:{effect_id}");
            let request = self.insert_effect_cancellation_request(EffectCancellationRequest {
                instance_id: activation.instance_id,
                effect_id,
                revision_id: Some(&revision_id),
                reason: Some("workflow revision"),
                requested_by: "workflow.revision",
                causation_event_id: Some(&event.event_id),
                idempotency_key: Some(&request_idempotency_key),
            })?;
            cancellation_request_ids.push((effect_id.clone(), request.request_id));
        }
        let revision_evidence_metadata = serde_json::json!({
            "revision_id": &revision_id,
            "event_id": event.event_id,
            "from_version_id": activation.from_version_id,
            "to_version_id": activation.to_version_id,
            "from_epoch": current_epoch,
            "to_epoch": next_epoch,
            "cancellation_policy": cancellation_policy,
            "terminal_cancel_effects": &queued_effects_for_policy,
            "request_cancel_effects": &running_effects_for_policy,
            "cancellation_request_ids": cancellation_request_ids
                .iter()
                .map(|(_, request_id)| request_id.as_str())
                .collect::<Vec<_>>(),
        })
        .to_string();
        let revision_evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: activation.instance_id,
                kind: "workflow.revision.activated",
                subject_type: "workflow_revision",
                subject_id: &revision_id,
                causation_id: Some(&event.event_id),
                correlation_id: Some(&revision_id),
                summary: Some("workflow revision activated"),
                metadata_json: &revision_evidence_metadata,
            },
        )?;
        let link = |target_type: &str, target_id: &str, relation: &str| {
            do_insert_evidence_link(
                &self.sql,
                EvidenceLink {
                    evidence_id: &revision_evidence_id,
                    instance_id: activation.instance_id,
                    target_type,
                    target_id,
                    relation,
                },
            )
        };
        link("event", &event.event_id, "activated")?;
        link(
            "program_version",
            activation.from_version_id,
            "from_version",
        )?;
        link("program_version", activation.to_version_id, "to_version")?;
        for effect_id in &queued_effects_for_policy {
            link("effect", effect_id, "terminal_cancelled")?;
        }
        for (effect_id, request_id) in &cancellation_request_ids {
            link("effect", effect_id, "cancellation_requested")?;
            link("effect_cancellation_request", request_id, "created")?;
        }
        do_revision_by_id(&self.sql, &revision_id)?
            .ok_or_else(|| StoreError::Conflict("revision was not recorded".to_owned()))
    }

    fn request_effect_cancellation(
        &mut self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView> {
        let status_rows = self
            .sql
            .query(
                "SELECT status FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
                &[text(request.instance_id), text(request.effect_id)],
            )
            .map_err(sql_err)?;
        let status = status_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| StoreError::Conflict("effect does not exist".to_owned()))?;
        if status != "running" {
            return Err(StoreError::Conflict(format!(
                "effect is {status}; cancellation requests require running work"
            )));
        }
        self.insert_effect_cancellation_request(request)
    }

    fn effect_has_open_cancellation_request(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<bool> {
        let rows = self
            .sql
            .query(
                "SELECT 1 FROM effect_cancellation_requests \
                 WHERE instance_id = ?1 AND effect_id = ?2 AND status = 'requested' LIMIT 1",
                &[text(instance_id), text(effect_id)],
            )
            .map_err(sql_err)?;
        Ok(!rows.is_empty())
    }

    fn list_effect_cancellation_requests(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<EffectCancellationRequestView>> {
        let rows = self
            .sql
            .query(
                "SELECT request_id, instance_id, effect_id, revision_id, reason, requested_by, \
                 causation_event_id, status, idempotency_key, created_at, updated_at, \
                 resolved_by_event_id FROM effect_cancellation_requests \
                 WHERE instance_id = ?1 ORDER BY created_at, request_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|r| effect_cancellation_request_from_row(r))
            .collect())
    }

    fn record_workflow_invocation(&self, invocation: NewWorkflowInvocation<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(invocation.input_json)?;
        let parent = self
            .sql
            .query(
                "SELECT program_version_id, revision_epoch FROM effects \
                 WHERE instance_id = ?1 AND effect_id = ?2",
                &[
                    text(invocation.parent_instance_id),
                    text(invocation.parent_effect_id),
                ],
            )
            .map_err(sql_err)?;
        let parent = parent.first().ok_or_else(|| {
            StoreError::Conflict("parent workflow invoke effect does not exist".to_owned())
        })?;
        let parent_program_version_id = as_opt_text(&parent[0]);
        let parent_revision_epoch = as_i64(&parent[1]);
        let child = self
            .sql
            .query(
                "SELECT version_id, revision_epoch FROM instances WHERE instance_id = ?1",
                &[text(invocation.child_instance_id)],
            )
            .map_err(sql_err)?;
        let child = child.first().ok_or_else(|| {
            StoreError::Conflict("child workflow instance does not exist".to_owned())
        })?;
        let child_program_version_id = as_text(&child[0]);
        let child_revision_epoch = as_i64(&child[1]);
        self.sql
            .execute(
                "INSERT INTO workflow_invocations (invocation_id, parent_instance_id, \
                 parent_effect_id, parent_program_version_id, parent_revision_epoch, \
                 child_instance_id, child_program_version_id, child_revision_epoch, \
                 target_workflow, input_json, source_span_json, idempotency_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(idempotency_key) DO NOTHING",
                &[
                    text(invocation.invocation_id),
                    text(invocation.parent_instance_id),
                    text(invocation.parent_effect_id),
                    opt_text(parent_program_version_id.as_deref()),
                    int(parent_revision_epoch),
                    text(invocation.child_instance_id),
                    text(&child_program_version_id),
                    int(child_revision_epoch),
                    text(invocation.target_workflow),
                    text(invocation.input_json),
                    opt_text(invocation.source_span_json),
                    text(invocation.idempotency_key),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        let sql = format!(
            "{WORKFLOW_INVOCATION_SELECT}WHERE workflow_invocations.parent_instance_id = ?1 \
             AND workflow_invocations.parent_effect_id = ?2 \
             ORDER BY workflow_invocations.created_at DESC, invocation_id DESC LIMIT 1"
        );
        let rows = self
            .sql
            .query(&sql, &[text(parent_instance_id), text(parent_effect_id)])
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| workflow_invocation_from_row(r)))
    }

    fn list_child_workflow_invocations(
        &self,
        parent_instance_id: &str,
    ) -> StoreResult<Vec<WorkflowInvocationView>> {
        let sql = format!(
            "{WORKFLOW_INVOCATION_SELECT}WHERE workflow_invocations.parent_instance_id = ?1 \
             ORDER BY workflow_invocations.created_at, invocation_id"
        );
        let rows = self
            .sql
            .query(&sql, &[text(parent_instance_id)])
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|r| workflow_invocation_from_row(r))
            .collect())
    }

    fn get_parent_workflow_invocation(
        &self,
        child_instance_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        let sql = format!(
            "{WORKFLOW_INVOCATION_SELECT}WHERE workflow_invocations.child_instance_id = ?1 \
             ORDER BY workflow_invocations.created_at DESC, invocation_id DESC LIMIT 1"
        );
        let rows = self
            .sql
            .query(&sql, &[text(child_instance_id)])
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| workflow_invocation_from_row(r)))
    }

    fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent> {
        self.commit_rule_inner(commit, None)
    }

    fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent> {
        self.commit_rule_inner(commit, Some(guard))
    }

    fn derive_fact(&mut self, derived: DerivedFact<'_>) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "fact_id": derived.fact.fact_id,
            "name": derived.fact.name,
            "key": derived.fact.key,
            "value": serde_json::from_str::<Value>(derived.fact.value_json)?,
            "schema_id": derived.fact.schema_id,
            "provenance_class": derived.fact.provenance_class,
            "correlation_id": derived.fact.correlation_id,
        })
        .to_string();
        // Replay-tolerant (native parity): a re-derivation under an existing
        // idempotency key is a crash-window heal; on replay the fact row is
        // inserted only if missing entirely, never revived from consumed.
        let mut replayed = false;
        let event = match derived.idempotency_key {
            Some(key) => {
                let existing = self
                    .sql
                    .query(
                        "SELECT event_id, sequence FROM events \
                         WHERE instance_id = ?1 AND idempotency_key = ?2",
                        &[text(derived.instance_id), text(key)],
                    )
                    .map_err(sql_err)?;
                match existing.first() {
                    Some(row) => {
                        replayed = true;
                        StoredEvent {
                            event_id: as_text(&row[0]),
                            sequence: as_i64(&row[1]),
                        }
                    }
                    None => do_append_event(
                        &self.sql,
                        NewEvent {
                            instance_id: derived.instance_id,
                            event_type: "fact.derived",
                            payload_json: &payload,
                            source: derived.source,
                            causation_id: derived.causation_id,
                            correlation_id: derived.fact.correlation_id,
                            idempotency_key: derived.idempotency_key,
                        },
                    )?,
                }
            }
            None => do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: derived.instance_id,
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: derived.source,
                    causation_id: derived.causation_id,
                    correlation_id: derived.fact.correlation_id,
                    idempotency_key: derived.idempotency_key,
                },
            )?,
        };
        let fact_row_exists = replayed
            && !self
                .sql
                .query(
                    "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 AND key = ?3",
                    &[
                        text(derived.instance_id),
                        text(derived.fact.name),
                        text(derived.fact.key),
                    ],
                )
                .map_err(sql_err)?
                .is_empty();
        if !fact_row_exists {
            let (program_version_id, revision_epoch) =
                do_active_revision(&self.sql, derived.instance_id)?;
            do_insert_fact(
                &self.sql,
                derived.instance_id,
                derived.source,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                &derived.fact,
            )?;
        }
        Ok(event)
    }

    fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome> {
        let (program_version_id, revision_epoch) =
            do_active_revision(&self.sql, batch.instance_id)?;
        let mut admitted = 0usize;
        let mut skipped = 0usize;
        for row in batch.rows {
            // Idempotent skip: a row whose derived key already produced a fact is
            // absorbed (the admitted-set membership guard).
            let exists = !self
                .sql
                .query(
                    "SELECT 1 FROM facts WHERE fact_id = ?1 AND instance_id = ?2",
                    &[text(row.fact_id), text(batch.instance_id)],
                )
                .map_err(sql_err)?
                .is_empty();
            if exists {
                skipped += 1;
                continue;
            }
            // Native parity: a LIVE identical row from an earlier admission is
            // a no-op re-assertion and counts `skipped`; a CONSUMED row falls
            // through to re-admit (DR-0044 revive) and counts `admitted`.
            let live_conflict = !self
                .sql
                .query(
                    "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 \
                     AND key = ?3 AND consumed_at IS NULL",
                    &[
                        text(batch.instance_id),
                        text(batch.schema_name),
                        text(row.key),
                    ],
                )
                .map_err(sql_err)?
                .is_empty();
            if live_conflict {
                skipped += 1;
                continue;
            }
            let value: Value = serde_json::from_str(row.value_json)?;
            let payload = serde_json::json!({
                "fact_id": row.fact_id,
                "name": batch.schema_name,
                "key": row.key,
                "value": value,
                "schema_id": batch.schema_id,
                "provenance_class": "import",
                "correlation_id": batch.correlation_id,
            })
            .to_string();
            let event = do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: batch.instance_id,
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: batch.source,
                    causation_id: batch.causation_id,
                    correlation_id: batch.correlation_id,
                    idempotency_key: Some(row.fact_id),
                },
            )?;
            do_insert_fact(
                &self.sql,
                batch.instance_id,
                batch.source,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                &NewFact {
                    fact_id: row.fact_id,
                    name: batch.schema_name,
                    key: row.key,
                    value_json: row.value_json,
                    schema_id: batch.schema_id,
                    provenance_class: "import",
                    correlation_id: batch.correlation_id,
                    source_span_json: None,
                },
            )?;
            admitted += 1;
        }
        Ok(FactBatchOutcome { admitted, skipped })
    }

    fn complete_effect(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        self.complete_effect_with_terminal_diagnostic(completion, None)
    }

    fn complete_effect_with_terminal_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        let run_status = completion.status;
        self.complete_effect_terminal_inner(completion, diagnostic, run_status)
    }

    fn resolve_effect_uncertain(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.complete_effect_terminal_inner(completion, diagnostic, "uncertain")
    }

    fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>> {
        // Only a running instance yields claimable work.
        let status_rows = self
            .sql
            .query(
                "SELECT status FROM instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = status_rows.first() {
            if as_text(&row[0]) != "running" {
                return Ok(Vec::new());
            }
        }
        let rows = self
            .sql
            .query(
                "SELECT candidate.effect_id, candidate.kind, candidate.target, candidate.profile, \
                 candidate.input_json, candidate.required_capabilities, \
                 COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]'), \
                 candidate.created_by_event_id, candidate.status \
                 FROM effects AS candidate \
                 LEFT JOIN instances ON instances.instance_id = candidate.instance_id \
                 LEFT JOIN program_versions AS active_versions \
                 ON active_versions.version_id = instances.version_id \
                 LEFT JOIN program_versions AS effect_versions \
                 ON effect_versions.version_id = candidate.program_version_id \
                 WHERE candidate.instance_id = ?1 AND candidate.kind != 'timer.wait' \
                 AND ( \
                   candidate.status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile') \
                   OR candidate.status = 'running' \
                 ) AND NOT EXISTS ( \
                   SELECT 1 FROM effect_cancellation_requests AS request \
                   WHERE request.instance_id = candidate.instance_id \
                     AND request.effect_id = candidate.effect_id AND request.status = 'requested' \
                 ) AND NOT EXISTS ( \
                   SELECT 1 FROM effect_dependencies AS dependency \
                   JOIN effects AS upstream ON upstream.effect_id = dependency.upstream_effect_id \
                    AND upstream.instance_id = dependency.instance_id \
                   WHERE dependency.instance_id = candidate.instance_id \
                     AND dependency.downstream_effect_id = candidate.effect_id AND NOT ( \
                       (dependency.predicate = 'succeeds' AND upstream.status = 'completed') \
                       OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out')) \
                       OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out') \
                       OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled') \
                       OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled')) \
                     ) \
                 ) ORDER BY candidate.created_at, candidate.effect_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        // RC-4b on the effects plane: orphaned-segment PENDING effects are
        // never handed to the worker after a restore (parity with native).
        let live = do_live_event_ids(&self.sql, instance_id)?;
        let mut claimable = Vec::new();
        for row in &rows {
            if let (Some(live), Some(event_id)) = (&live, as_opt_text(&row[7])) {
                if !live.contains(&event_id) {
                    continue;
                }
            }
            let effect = ClaimableEffect {
                effect_id: as_text(&row[0]),
                kind: as_text(&row[1]),
                target: as_opt_text(&row[2]),
                profile: as_opt_text(&row[3]),
                input_json: as_text(&row[4]),
                required_capabilities_json: as_text(&row[5]),
                declared_profiles_json: as_text(&row[6]),
            };
            if let Some(block) = do_policy_block(&self.sql, instance_id, &effect.effect_id)? {
                // Persist the block where it is observed (parity with native
                // `persist_policy_block_on`): a silent skip left the effect
                // reading `queued` with no reason forever.
                do_persist_policy_block(&self.sql, instance_id, &effect.effect_id, &block)?;
                continue;
            }
            let already_running = as_text(&row[8]) == "running";
            if !already_running
                && do_capacity_block(&self.sql, instance_id, &effect.effect_id)?.is_some()
            {
                continue;
            }
            claimable.push(effect);
        }
        Ok(claimable)
    }

    fn fact_exists(&self, instance_id: &str, fact_name: &str) -> StoreResult<bool> {
        let rows = self
            .sql
            .query(
                "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 LIMIT 1",
                &[text(instance_id), text(fact_name)],
            )
            .map_err(sql_err)?;
        Ok(!rows.is_empty())
    }

    fn register_package(&self, package: PackageRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(package.manifest_json)?;
        self.sql
            .execute(
                "INSERT INTO package_registrations (package_id, name, version, manifest_json) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(package_id) DO UPDATE SET \
                 name = excluded.name, version = excluded.version, \
                 manifest_json = excluded.manifest_json",
                &[
                    text(package.package_id),
                    text(package.name),
                    text(package.version),
                    text(package.manifest_json),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn register_package_manifest(&self, manifest_json: &str) -> StoreResult<String> {
        let manifest: Value = serde_json::from_str(manifest_json)?;
        let package_id = required_manifest_string(&manifest, &["package_id", "plugin_id"])?;
        let name = required_manifest_string(&manifest, &["name"])?;
        let version = required_manifest_string(&manifest, &["version"])?;

        self.register_package(PackageRegistration {
            package_id: &package_id,
            name: &name,
            version: &version,
            manifest_json,
        })?;

        for capability in manifest
            .get("capabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let schema_json = capability
                .get("schema")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.register_capability_schema(CapabilitySchemaRegistration {
                capability: &required_manifest_string(capability, &["capability", "id"])?,
                description: capability
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                schema_json: &schema_json,
                registered_by_package_id: Some(&package_id),
            })?;
        }

        for provider in manifest
            .get("providers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // Operator-plane rows (`"plane": "operator"`, std-telemetry.md
            // T3) are capability-free operator-CLI configuration, never an
            // admission-plane registration — parity with the native store.
            if provider.get("plane").and_then(Value::as_str) == Some("operator") {
                continue;
            }
            let config_json = provider
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.register_effect_provider(EffectProviderRegistration {
                provider_id: &required_manifest_string(provider, &["provider_id", "id"])?,
                effect_kind: &manifest_effect_kind(provider),
                provider: &required_manifest_string(
                    provider,
                    &["provider", "provider_kind", "kind"],
                )?,
                capability: &required_manifest_string(
                    provider,
                    &["capability", "effect_contract", "effect_contract_id"],
                )?,
                config_json: &config_json,
                registered_by_package_id: Some(&package_id),
            })?;
        }

        for profile in manifest
            .get("profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let config_json = profile
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            let allowed_json = profile
                .get("allowed_capabilities")
                .map(Value::to_string)
                .unwrap_or_else(|| "[]".to_owned());
            self.register_profile(ProfileRegistration {
                profile_id: &required_manifest_string(profile, &["profile_id", "id"])?,
                name: &required_string(profile, "name"),
                description: profile
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                enforcement_mode: profile
                    .get("enforcement_mode")
                    .and_then(Value::as_str)
                    .unwrap_or("enforce"),
                allowed_capabilities_json: &allowed_json,
                config_json: &config_json,
            })?;
        }

        for binding in manifest
            .get("bindings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let config_json = binding
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.bind_capability(CapabilityBinding {
                binding_id: &required_manifest_string(binding, &["binding_id", "id"])?,
                program_id: binding.get("program_id").and_then(Value::as_str),
                capability: &required_manifest_string(binding, &["capability"])?,
                provider: &required_manifest_string(binding, &["provider", "provider_kind"])?,
                config_json: &config_json,
            })?;
        }

        Ok(package_id)
    }

    fn register_capability_schema(
        &self,
        capability: CapabilitySchemaRegistration<'_>,
    ) -> StoreResult<()> {
        serde_json::from_str::<Value>(capability.schema_json)?;
        self.sql.execute(
            "INSERT INTO capability_schemas (capability, description, schema_json, registered_by_package_id) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(capability) DO UPDATE SET description = excluded.description, schema_json = excluded.schema_json, registered_by_package_id = excluded.registered_by_package_id",
            &[text(capability.capability), text(capability.description), text(capability.schema_json), opt_text(capability.registered_by_package_id)],
        ).map_err(sql_err)?;
        Ok(())
    }

    fn register_effect_provider(
        &self,
        provider: EffectProviderRegistration<'_>,
    ) -> StoreResult<()> {
        serde_json::from_str::<Value>(provider.config_json)?;
        self.sql.execute(
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json, registered_by_package_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(effect_kind, provider) DO UPDATE SET capability = excluded.capability, config_json = excluded.config_json, registered_by_package_id = excluded.registered_by_package_id",
            &[text(provider.provider_id), text(provider.effect_kind), text(provider.provider), text(provider.capability), text(provider.config_json), opt_text(provider.registered_by_package_id)],
        ).map_err(sql_err)?;
        Ok(())
    }

    // DR-0062 §6 provider-trust evidence, DO parity: the SAME table, the same
    // upsert keys, and the same rule that a filed claim carries a term (the
    // CHECK rides in `do_schema.sql`). Derivation is deliberately NOT here —
    // `provider_trust::derive` in the kernel is the one place that decides what
    // evidence supports, so the two placements cannot drift on the ladder.
    fn pin_provider_endpoint(
        &self,
        effect_kind: &str,
        provider: &str,
        digest: &str,
    ) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO provider_trust_evidence (effect_kind, provider, pinned_digest) VALUES (?1, ?2, ?3) ON CONFLICT(effect_kind, provider) DO UPDATE SET pinned_digest = excluded.pinned_digest, updated_at = CURRENT_TIMESTAMP",
                &[text(effect_kind), text(provider), text(digest)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn file_provider_custody_claim(&self, claim: ProviderCustodyClaim<'_>) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO provider_trust_evidence (effect_kind, provider, claim_class, claim_signer, claim_filed_at, claim_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(effect_kind, provider) DO UPDATE SET claim_class = excluded.claim_class, claim_signer = excluded.claim_signer, claim_filed_at = excluded.claim_filed_at, claim_expires_at = excluded.claim_expires_at, updated_at = CURRENT_TIMESTAMP",
                &[
                    text(claim.effect_kind),
                    text(claim.provider),
                    text(claim.class),
                    text(claim.signer),
                    text(claim.filed_at),
                    text(claim.expires_at),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn set_provider_operator_run(
        &self,
        effect_kind: &str,
        provider: &str,
        operator_run: bool,
    ) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO provider_trust_evidence (effect_kind, provider, operator_run) VALUES (?1, ?2, ?3) ON CONFLICT(effect_kind, provider) DO UPDATE SET operator_run = excluded.operator_run, updated_at = CURRENT_TIMESTAMP",
                &[
                    text(effect_kind),
                    text(provider),
                    int(i64::from(operator_run)),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn provider_trust_evidence(
        &self,
        effect_kind: &str,
        provider: &str,
    ) -> StoreResult<Option<ProviderTrustRow>> {
        let rows = self
            .sql
            .query(
                "SELECT pinned_digest, claim_class, claim_signer, claim_filed_at, claim_expires_at, operator_run FROM provider_trust_evidence WHERE effect_kind = ?1 AND provider = ?2",
                &[text(effect_kind), text(provider)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        Ok(Some(ProviderTrustRow {
            pinned_digest: row.first().and_then(as_opt_text),
            claim_class: row.get(1).and_then(as_opt_text),
            claim_signer: row.get(2).and_then(as_opt_text),
            claim_filed_at: row.get(3).and_then(as_opt_text),
            claim_expires_at: row.get(4).and_then(as_opt_text),
            operator_run: row.get(5).map(as_i64).unwrap_or(0) != 0,
        }))
    }

    fn register_profile(&self, profile: ProfileRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(profile.allowed_capabilities_json)?;
        serde_json::from_str::<Value>(profile.config_json)?;
        self.sql.execute(
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(name) DO UPDATE SET description = excluded.description, enforcement_mode = excluded.enforcement_mode, allowed_capabilities = excluded.allowed_capabilities, config_json = excluded.config_json",
            &[text(profile.profile_id), text(profile.name), text(profile.description), text(profile.enforcement_mode), text(profile.allowed_capabilities_json), text(profile.config_json)],
        ).map_err(sql_err)?;
        Ok(())
    }

    fn registered_profile_policy(
        &self,
        profile: &str,
    ) -> StoreResult<Option<RegisteredProfilePolicy>> {
        let rows = self
            .sql
            .query(
                "SELECT enforcement_mode, allowed_capabilities FROM profiles WHERE name = ?1",
                &[text(profile)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let enforcement_mode = as_text(&row[0]);
        let allowed_capabilities = serde_json::from_str::<Value>(&as_text(&row[1]))?
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(Some(RegisteredProfilePolicy {
            enforcement_mode,
            allowed_capabilities,
        }))
    }

    fn bind_capability(&self, binding: CapabilityBinding<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(binding.config_json)?;
        self.sql.execute(
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(binding_id) DO UPDATE SET program_id = excluded.program_id, capability = excluded.capability, provider = excluded.provider, config_json = excluded.config_json",
            &[text(binding.binding_id), opt_text(binding.program_id), text(binding.capability), text(binding.provider), text(binding.config_json)],
        ).map_err(sql_err)?;
        Ok(())
    }

    fn register_project_context_doc(
        &self,
        position: i64,
        path: &str,
        body: &str,
    ) -> StoreResult<()> {
        // Content-addressed like skills: byte-identical hash across backends.
        let content_hash = stable_hash_hex(body);
        self.sql
            .execute(
                "INSERT OR REPLACE INTO project_context_docs (position, path, content_hash, body) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[int(position), text(path), text(&content_hash), text(body)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn list_project_context_docs(&self) -> StoreResult<Vec<ProjectContextDoc>> {
        let rows = self
            .sql
            .query(
                "SELECT position, path, content_hash, body FROM project_context_docs \
                 ORDER BY position",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| ProjectContextDoc {
                position: as_i64(&row[0]),
                path: as_text(&row[1]),
                content_hash: as_text(&row[2]),
                body: as_text(&row[3]),
            })
            .collect())
    }

    fn record_compute_result(
        &self,
        registration: ComputeResultRegistration<'_>,
    ) -> StoreResult<bool> {
        let inserted = self
            .sql
            .execute(
                "INSERT OR IGNORE INTO compute_result_cache \
                 (content_key, effect_kind, result_json, source_instance_id, source_effect_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text(registration.content_key),
                    text(registration.effect_kind),
                    text(registration.result_json),
                    text(registration.source_instance_id),
                    text(registration.source_effect_id),
                ],
            )
            .map_err(sql_err)?;
        Ok(inserted > 0)
    }

    fn lookup_compute_result(&self, content_key: &str) -> StoreResult<Option<ComputeCachedResult>> {
        let rows = self
            .sql
            .query(
                "SELECT content_key, effect_kind, result_json, source_instance_id, \
                 source_effect_id, created_at FROM compute_result_cache WHERE content_key = ?1",
                &[text(content_key)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| ComputeCachedResult {
            content_key: as_text(&row[0]),
            effect_kind: as_text(&row[1]),
            result_json: as_text(&row[2]),
            source_instance_id: as_text(&row[3]),
            source_effect_id: as_text(&row[4]),
            created_at: as_text(&row[5]),
        }))
    }

    fn put_content(&self, body: &str) -> StoreResult<String> {
        // RC-1 file-history capture over DO SQLite: same content id + same
        // dedup (INSERT OR IGNORE) as the native/recall content store, in the
        // same DO SQLite as the write's fact and before that fact commits, so no
        // manifest hash is ever referenced without its bytes (INV-4 coherence).
        let id = stable_hash_hex(body);
        self.sql
            .execute(
                "INSERT OR IGNORE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
                &[text(&id), text(body), int(body.len() as i64)],
            )
            .map_err(sql_err)?;
        Ok(id)
    }

    fn get_content(&self, id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query("SELECT body FROM content_blobs WHERE id = ?1", &[text(id)])
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn capture_checkpoint(
        &mut self,
        capture: CheckpointCapture<'_>,
    ) -> StoreResult<CapturedCheckpoint> {
        // INV-2 no-in-flight straddle: a checkpoint is a consistent cut only at
        // a quiescent point; refuse if any effect is mid-run.
        let running_rows = self
            .sql
            .query(
                "SELECT COUNT(*) FROM effects WHERE instance_id = ?1 AND status = 'running'",
                &[text(capture.instance_id)],
            )
            .map_err(sql_err)?;
        let running = running_rows.first().map(|row| as_i64(&row[0])).unwrap_or(0);
        if running > 0 {
            return Err(StoreError::Conflict(format!(
                "checkpoint requires a quiescent instance; {running} effect(s) still running"
            )));
        }
        // RC-4c: fold the manifest from the LIVE fact.derived payloads (the
        // restore-marker fold applied), so a checkpoint after a restore reflects
        // the reconciled file plane, never an abandoned-branch write. The
        // checkpoint event appended below is not a file write, so folding over
        // the current head equals folding <= the checkpoint's own sequence.
        let fact_payloads = do_live_fact_payloads(&self.sql, capture.instance_id, None)?;
        let (manifest_json, manifest) = do_fold_file_manifest(&fact_payloads)?;
        // INV-4 coherence: store the manifest content-addressed BEFORE the cut
        // references its hash (same DO SQLite), so no committed cut names a
        // manifest hash absent from the blob store.
        let manifest_hash = stable_hash_hex(&manifest_json);
        self.sql
            .execute(
                "INSERT OR IGNORE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
                &[
                    text(&manifest_hash),
                    text(&manifest_json),
                    int(manifest_json.len() as i64),
                ],
            )
            .map_err(sql_err)?;
        let payload = serde_json::json!({
            "cut_id": capture.cut_id,
            "transcript_ref": capture.transcript_ref,
            "manifest_hash": manifest_hash,
            "manifest": manifest,
            "file_count": manifest.len(),
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: capture.instance_id,
                event_type: "context.checkpoint",
                payload_json: &payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key: capture.idempotency_key,
            },
        )?;
        Ok(CapturedCheckpoint {
            cut_id: capture.cut_id.to_owned(),
            event_id: event.event_id,
            sequence: event.sequence,
            manifest_hash,
            file_count: manifest.len(),
        })
    }

    fn plan_restore(&self, instance_id: &str, cut_id: &str) -> StoreResult<RestoreDecision> {
        // Resolve the checkpoint by cut id (latest first).
        let checkpoint_rows = self
            .sql
            .query(
                "SELECT payload_json, sequence FROM events \
                 WHERE instance_id = ?1 AND event_type = 'context.checkpoint' ORDER BY sequence DESC",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        let resolved = checkpoint_rows.iter().find_map(|row| {
            let payload_json = as_text(&row[0]);
            let payload: Value = serde_json::from_str(&payload_json).ok()?;
            (payload.get("cut_id").and_then(Value::as_str) == Some(cut_id))
                .then(|| (payload, as_i64(&row[1])))
        });
        let Some((payload, restored_to_sequence)) = resolved else {
            return Ok(RestoreDecision::Refused {
                reason: format!("no checkpoint with cut id `{cut_id}`"),
            });
        };
        let manifest_hash = payload
            .get("manifest_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let transcript_ref = payload
            .get("transcript_ref")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let Some(manifest_body) = self.get_content(&manifest_hash)? else {
            return Ok(RestoreDecision::Refused {
                reason: format!("manifest blob `{manifest_hash}` missing for cut `{cut_id}`"),
            });
        };
        let cut_manifest: BTreeMap<String, String> = serde_json::from_str(&manifest_body)?;
        // INV-4 coherence: every referenced content hash present, up front.
        let mut writes: BTreeMap<String, String> = BTreeMap::new();
        for (path, content_hash) in &cut_manifest {
            match self.get_content(content_hash)? {
                Some(body) => {
                    writes.insert(path.clone(), body);
                }
                None => {
                    return Ok(RestoreDecision::Refused {
                        reason: format!(
                            "content `{content_hash}` for `{path}` missing (dangling manifest)"
                        ),
                    });
                }
            }
        }
        // Full reconcile: mediated paths live now but absent from the cut.
        let current_payloads = do_live_fact_payloads(&self.sql, instance_id, None)?;
        let (_, current_manifest) = do_fold_file_manifest(&current_payloads)?;
        let removes: Vec<String> = current_manifest
            .keys()
            .filter(|path| !cut_manifest.contains_key(*path))
            .cloned()
            .collect();
        Ok(RestoreDecision::Ready(RestorePlan {
            cut_id: cut_id.to_owned(),
            restored_to_sequence,
            transcript_ref,
            writes,
            removes,
        }))
    }

    fn commit_restore(
        &mut self,
        instance_id: &str,
        restored_to_sequence: i64,
        cut_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "cut_id": cut_id,
            "restored_to_sequence": restored_to_sequence,
        })
        .to_string();
        let marker = do_append_event(
            &self.sql,
            NewEvent {
                instance_id,
                event_type: "context.restored",
                payload_json: &payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key,
            },
        )?;
        self.rebuild_projections(instance_id)?;
        Ok(marker)
    }

    fn register_script_capability(
        &self,
        registration: ScriptCapabilityRegistration<'_>,
    ) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT OR REPLACE INTO script_capabilities \
                 (name, argv_json, sha256, env_json, hermetic, body) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    text(registration.name),
                    text(registration.argv_json),
                    text(registration.sha256),
                    text(registration.env_json),
                    int(i64::from(registration.hermetic)),
                    text(registration.body),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn get_script_capability(&self, name: &str) -> StoreResult<Option<ScriptCapabilityRecord>> {
        let rows = self
            .sql
            .query(
                "SELECT name, argv_json, sha256, env_json, hermetic, body \
                 FROM script_capabilities WHERE name = ?1",
                &[text(name)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| ScriptCapabilityRecord {
            name: as_text(&row[0]),
            argv_json: as_text(&row[1]),
            sha256: as_text(&row[2]),
            env_json: as_text(&row[3]),
            hermetic: as_i64(&row[4]) != 0,
            body: as_text(&row[5]),
        }))
    }

    fn register_skill(&self, skill: SkillRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(skill.required_capabilities_json)?;
        serde_json::from_str::<Value>(skill.metadata_json)?;
        // Content-address the body (Decision 3); byte-identical to the native
        // store so a skill's hash matches across backends.
        let content_hash = stable_hash_hex(skill.body);
        self.sql
            .execute(
                "INSERT INTO skills (skill_id, name, version, source, source_path, \
                 content_hash, body, description, required_capabilities, metadata_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) ON CONFLICT(name) DO UPDATE SET \
                 version = excluded.version, source = excluded.source, \
                 source_path = excluded.source_path, content_hash = excluded.content_hash, \
                 body = excluded.body, description = excluded.description, \
                 required_capabilities = excluded.required_capabilities, \
                 metadata_json = excluded.metadata_json",
                &[
                    text(skill.skill_id),
                    text(skill.name),
                    text(skill.version),
                    text(skill.source),
                    text(skill.source_path),
                    text(&content_hash),
                    text(skill.body),
                    text(skill.description),
                    text(skill.required_capabilities_json),
                    text(skill.metadata_json),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn attach_skill(&self, attachment: SkillAttachment<'_>) -> StoreResult<()> {
        let rows = self
            .sql
            .query(
                "SELECT skill_id FROM skills WHERE name = ?1",
                &[text(attachment.skill_name)],
            )
            .map_err(sql_err)?;
        let skill_id = rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err(format!("no skill named `{}`", attachment.skill_name)))?;
        self.sql
            .execute(
                "INSERT INTO skill_attachments (attachment_id, scope_type, scope_id, skill_id) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(scope_type, scope_id, skill_id) DO NOTHING",
                &[
                    text(attachment.attachment_id),
                    text(attachment.scope_type),
                    text(attachment.scope_id),
                    text(&skill_id),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn list_skills(&self) -> StoreResult<Vec<SkillView>> {
        let rows = self
            .sql
            .query(
                "SELECT skill_id, name, version, source, source_path, content_hash, \
                 description, required_capabilities FROM skills ORDER BY name",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| skill_view_from_row(r)).collect())
    }

    fn list_skill_attachments(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> StoreResult<Vec<SkillAttachmentView>> {
        let rows = self
            .sql
            .query(
                "SELECT attachment.attachment_id, attachment.scope_type, attachment.scope_id, \
                 skill.skill_id, skill.name, skill.version, skill.source, skill.source_path, \
                 skill.content_hash, skill.description, skill.required_capabilities \
                 FROM skill_attachments AS attachment \
                 JOIN skills AS skill ON skill.skill_id = attachment.skill_id \
                 WHERE attachment.scope_type = ?1 AND attachment.scope_id = ?2 \
                 ORDER BY skill.name",
                &[text(scope_type), text(scope_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|r| SkillAttachmentView {
                attachment_id: as_text(&r[0]),
                scope_type: as_text(&r[1]),
                scope_id: as_text(&r[2]),
                skill: skill_view_from_row(&r[3..11]),
            })
            .collect())
    }

    fn record_evidence(&self, evidence: EvidenceRecord<'_>) -> StoreResult<String> {
        do_insert_evidence(&self.sql, evidence)
    }

    fn record_provider_validation_evidence(
        &self,
        evidence: ProviderValidationEvidence<'_>,
    ) -> StoreResult<String> {
        let config = serde_json::from_str::<Value>(evidence.config_json)?;
        let capability = serde_json::from_str::<Value>(evidence.capability_json)?;
        let validation_results = serde_json::from_str::<Value>(evidence.validation_results_json)?;
        let metadata = serde_json::json!({
            "provider_id": evidence.provider_id,
            "provider_kind": evidence.provider_kind,
            "surface": evidence.surface,
            "status": evidence.status,
            "source_path": evidence.source_path,
            "config": config,
            "capability": capability,
            "validation_results": validation_results,
        })
        .to_string();
        let summary = format!(
            "provider `{}` validation {} on {}",
            evidence.provider_id, evidence.status, evidence.surface
        );
        let evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "provider.validation",
                subject_type: "provider_config",
                subject_id: evidence.provider_id,
                causation_id: None,
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "validates",
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_capability",
                target_id: &format!("{}:{}", evidence.provider_kind, evidence.surface),
                relation: "uses",
            },
        )?;
        Ok(evidence_id)
    }

    fn record_codex_app_server_evidence(
        &self,
        evidence: CodexAppServerEvidence<'_>,
    ) -> StoreResult<String> {
        let inner = serde_json::from_str::<Value>(evidence.metadata_json)?;
        let metadata = serde_json::json!({
            "provider_id": evidence.provider_id,
            "thread_id": evidence.thread_id,
            "turn_id": evidence.turn_id,
            "evidence": inner,
        })
        .to_string();
        let summary = format!(
            "Codex app-server evidence for provider `{}` turn `{}`",
            evidence.provider_id, evidence.turn_id
        );
        let evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "codex.app_server.evidence",
                subject_type: "provider_turn",
                subject_id: evidence.turn_id,
                causation_id: None,
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "observes",
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_thread",
                target_id: evidence.thread_id,
                relation: "observes",
            },
        )?;
        Ok(evidence_id)
    }

    fn record_claude_agent_sdk_evidence(
        &self,
        evidence: ClaudeAgentSdkEvidence<'_>,
    ) -> StoreResult<String> {
        let inner = serde_json::from_str::<Value>(evidence.metadata_json)?;
        let metadata = serde_json::json!({
            "provider_id": evidence.provider_id,
            "session_id": evidence.session_id,
            "run_id": evidence.run_id,
            "evidence": inner,
        })
        .to_string();
        let summary = format!(
            "Claude Agent SDK evidence for provider `{}` session `{}`",
            evidence.provider_id, evidence.session_id
        );
        let evidence_id = do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "claude.agent_sdk.evidence",
                subject_type: "provider_session",
                subject_id: evidence.session_id,
                causation_id: Some(evidence.run_id),
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "observes",
            },
        )?;
        do_insert_evidence_link(
            &self.sql,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_run",
                target_id: evidence.run_id,
                relation: "observes",
            },
        )?;
        Ok(evidence_id)
    }

    fn link_evidence(&self, link: EvidenceLink<'_>) -> StoreResult<()> {
        do_insert_evidence_link(&self.sql, link)
    }

    fn record_artifact(&self, artifact: ArtifactRecord<'_>) -> StoreResult<String> {
        let rows = self
            .sql
            .query(
                "INSERT INTO artifacts (artifact_id, run_id, kind, path, content_hash, mime_type) \
                 VALUES ('art_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5) \
                 RETURNING artifact_id",
                &[
                    text(artifact.run_id),
                    text(artifact.kind),
                    text(artifact.path),
                    opt_text(artifact.content_hash),
                    opt_text(artifact.mime_type),
                ],
            )
            .map_err(sql_err)?;
        rows.first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| sql_err("record_artifact returned no row".to_string()))
    }

    fn list_artifacts_for_run(&self, run_id: &str) -> StoreResult<Vec<ArtifactView>> {
        let rows = self
            .sql
            .query(
                "SELECT artifact_id, run_id, kind, path, content_hash, mime_type, created_at \
                 FROM artifacts WHERE run_id = ?1 ORDER BY created_at, artifact_id",
                &[text(run_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| artifact_from_row(r)).collect())
    }

    fn record_workspace(&self, workspace: WorkspaceRecord<'_>) -> StoreResult<String> {
        validate_workspace_policy(workspace.policy)?;
        validate_workspace_status(workspace.status)?;
        serde_json::from_str::<Value>(workspace.metadata_json)?;
        let rows = self
            .sql
            .query(
                "INSERT INTO workspaces (workspace_id, instance_id, effect_id, run_id, provider, \
                 policy, uri, status, metadata_json, updated_at) VALUES \
                 ('wsp_' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
                 CURRENT_TIMESTAMP) ON CONFLICT(instance_id, effect_id, run_id, policy) \
                 DO UPDATE SET provider = excluded.provider, uri = excluded.uri, \
                 status = excluded.status, metadata_json = excluded.metadata_json, \
                 updated_at = CURRENT_TIMESTAMP RETURNING workspace_id",
                &[
                    opt_text(workspace.instance_id),
                    opt_text(workspace.effect_id),
                    opt_text(workspace.run_id),
                    opt_text(workspace.provider),
                    text(workspace.policy),
                    text(workspace.uri),
                    text(workspace.status),
                    text(workspace.metadata_json),
                ],
            )
            .map_err(sql_err)?;
        let row = rows
            .first()
            .ok_or_else(|| sql_err("record_workspace returned no row".to_string()))?;
        Ok(as_text(&row[0]))
    }

    fn get_workspace(&self, workspace_id: &str) -> StoreResult<Option<WorkspaceView>> {
        let rows = self
            .sql
            .query(
                &workspace_select_sql("WHERE workspace_id = ?1"),
                &[text(workspace_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| workspace_from_row(r)))
    }

    fn list_workspaces_for_instance(&self, instance_id: &str) -> StoreResult<Vec<WorkspaceView>> {
        let rows = self
            .sql
            .query(
                &workspace_select_sql("WHERE instance_id = ?1 ORDER BY created_at, workspace_id"),
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| workspace_from_row(r)).collect())
    }

    fn record_diagnostic(&self, diagnostic: DiagnosticRecord<'_>) -> StoreResult<String> {
        do_insert_diagnostic(&self.sql, diagnostic)
    }

    fn list_diagnostics(&self, instance_id: Option<&str>) -> StoreResult<Vec<DiagnosticView>> {
        let mut sql = "SELECT diagnostic_id, instance_id, program_id, program_version_id, \
             severity, code, message, source_span_json, subject_type, subject_id, event_id, \
             effect_id, run_id, assertion_id, evidence_ids_json, artifact_ids_json, causation_id, \
             correlation_id, idempotency_key, created_at FROM diagnostics"
            .to_owned();
        if instance_id.is_some() {
            sql.push_str(" WHERE instance_id = ?1");
        }
        sql.push_str(" ORDER BY created_at, diagnostic_id");
        let params: Vec<SqlValue> = instance_id.map(|i| vec![text(i)]).unwrap_or_default();
        let rows = self.sql.query(&sql, &params).map_err(sql_err)?;
        Ok(rows.iter().map(|r| diagnostic_from_row(r)).collect())
    }

    fn list_diagnostics_from_events(&self, instance_id: &str) -> StoreResult<Vec<DiagnosticView>> {
        let rows = self
            .sql
            .query(
                "SELECT event_id, payload_json, occurred_at FROM events \
                 WHERE instance_id = ?1 AND event_type = 'effect.terminal' ORDER BY sequence",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        let mut diagnostics = Vec::new();
        for row in &rows {
            let event_id = as_text(&row[0]);
            let payload = serde_json::from_str::<Value>(&as_text(&row[1]))?;
            let occurred_at = as_text(&row[2]);
            let Some(diagnostic) = payload.get("diagnostic").filter(|value| !value.is_null())
            else {
                continue;
            };
            diagnostics.push(DiagnosticView {
                diagnostic_id: format!("dia_event_{}", stable_hash_hex(&event_id)),
                instance_id: Some(instance_id.to_owned()),
                program_id: optional_string(diagnostic.get("program_id")),
                program_version_id: optional_string(diagnostic.get("program_version_id")),
                severity: optional_string(diagnostic.get("severity"))
                    .unwrap_or_else(|| "error".to_owned()),
                code: optional_string(diagnostic.get("code")),
                message: optional_string(diagnostic.get("message")).unwrap_or_default(),
                source_span_json: diagnostic.get("source_span").and_then(|value| {
                    if value.is_null() {
                        None
                    } else {
                        Some(value.to_string())
                    }
                }),
                subject_type: optional_string(diagnostic.get("subject_type")),
                subject_id: optional_string(diagnostic.get("subject_id")),
                event_id: Some(event_id.clone()),
                effect_id: optional_string(payload.get("effect_id")),
                run_id: optional_string(payload.get("run_id")),
                assertion_id: optional_string(diagnostic.get("assertion_id")),
                evidence_ids_json: diagnostic
                    .get("evidence_ids")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([]))
                    .to_string(),
                artifact_ids_json: diagnostic
                    .get("artifact_ids")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([]))
                    .to_string(),
                causation_id: optional_string(diagnostic.get("causation_id")),
                correlation_id: optional_string(diagnostic.get("correlation_id")),
                idempotency_key: optional_string(diagnostic.get("idempotency_key")),
                created_at: occurred_at,
            });
        }
        Ok(diagnostics)
    }

    fn effect_source_span_json(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT events.payload_json FROM effects \
                 JOIN events ON events.event_id = effects.created_by_event_id \
                 WHERE effects.instance_id = ?1 AND effects.effect_id = ?2",
                &[text(instance_id), text(effect_id)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let payload = serde_json::from_str::<Value>(&as_text(&row[0]))?;
        let span = payload
            .get("effects")
            .and_then(Value::as_array)
            .and_then(|effects| {
                effects.iter().find_map(|effect| {
                    (effect.get("effect_id").and_then(Value::as_str) == Some(effect_id))
                        .then(|| effect.get("source_span"))
                        .flatten()
                        .filter(|value| !value.is_null())
                        .map(Value::to_string)
                })
            });
        Ok(span)
    }

    fn record_skill_evidence(&self, evidence: SkillEvidence<'_>) -> StoreResult<String> {
        // Resolve each named skill (sorted by name), mirroring `skills_by_name`.
        let mut skills = Vec::new();
        for name in evidence.skill_names {
            let rows = self
                .sql
                .query(
                    "SELECT skill_id, name, version, source, source_path, content_hash, \
                     description, required_capabilities FROM skills WHERE name = ?1",
                    &[text(name)],
                )
                .map_err(sql_err)?;
            let row = rows
                .first()
                .ok_or_else(|| sql_err(format!("no skill named `{name}`")))?;
            skills.push(skill_view_from_row(row));
        }
        skills.sort_by(|left, right| left.name.cmp(&right.name));
        let metadata = serde_json::json!({
            "effect_id": evidence.effect_id,
            "skills": skills.iter().map(skill_to_json).collect::<StoreResult<Vec<_>>>()?,
        })
        .to_string();
        let summary = if skills.is_empty() {
            "no skills injected".to_owned()
        } else {
            format!(
                "injected skills: {}",
                skills
                    .iter()
                    .map(|skill| format!("{}@{}", skill.name, skill.version))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        do_insert_evidence(
            &self.sql,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "skills.injected",
                subject_type: "run",
                subject_id: evidence.run_id,
                causation_id: Some(evidence.effect_id),
                correlation_id: evidence.idempotency_key,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )
    }

    fn list_evidence(&self, instance_id: &str) -> StoreResult<Vec<EvidenceView>> {
        let rows = self
            .sql
            .query(
                "SELECT evidence_id, instance_id, kind, subject_type, subject_id, causation_id, \
                 correlation_id, summary, metadata_json, created_at FROM evidence \
                 WHERE instance_id = ?1 ORDER BY created_at, evidence_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| evidence_from_row(r)).collect())
    }

    fn list_evidence_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<EvidenceView>> {
        let rows = self
            .sql
            .query(
                "SELECT evidence_id, instance_id, kind, subject_type, subject_id, causation_id, \
                 correlation_id, summary, metadata_json, created_at FROM evidence \
                 WHERE subject_type = ?1 AND subject_id = ?2 ORDER BY created_at, evidence_id",
                &[text(subject_type), text(subject_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| evidence_from_row(r)).collect())
    }

    fn list_evidence_links(&self, instance_id: &str) -> StoreResult<Vec<EvidenceLinkView>> {
        let rows = self
            .sql
            .query(
                "SELECT evidence_id, target_type, target_id, relation, created_at \
                 FROM evidence_links WHERE instance_id = ?1 \
                 ORDER BY created_at, evidence_id, target_type, target_id, relation",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| evidence_link_from_row(r)).collect())
    }

    fn list_instances(&self) -> StoreResult<Vec<InstanceView>> {
        let rows = self
            .sql
            .query(
                "SELECT instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json, created_at, \
                 updated_at FROM instances ORDER BY created_at, instance_id",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| instance_view_from_row(r)).collect())
    }

    fn get_instance(&self, instance_id: &str) -> StoreResult<Option<InstanceView>> {
        let rows = self
            .sql
            .query(
                "SELECT instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json, created_at, \
                 updated_at FROM instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| instance_view_from_row(r)))
    }

    fn list_events(&self, instance_id: &str) -> StoreResult<Vec<EventView>> {
        let rows = self
            .sql
            .query(
                "SELECT event_id, sequence, event_type, payload_json, source, occurred_at \
                 FROM events WHERE instance_id = ?1 ORDER BY sequence",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| event_view_from_row(r)).collect())
    }

    fn event_by_idempotency_key(
        &self,
        instance_id: &str,
        idempotency_key: &str,
    ) -> StoreResult<Option<StoredEvent>> {
        let rows = self
            .sql
            .query(
                "SELECT event_id, sequence FROM events \
                 WHERE instance_id = ?1 AND idempotency_key = ?2",
                &[text(instance_id), text(idempotency_key)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| StoredEvent {
            event_id: as_text(&row[0]),
            sequence: as_i64(&row[1]),
        }))
    }

    fn list_facts(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        let rows = self
            .sql
            .query(
                "SELECT fact_id, program_version_id, revision_epoch, name, key, value_json, \
                 provenance_class, source_span_json, source_event_id FROM facts \
                 WHERE instance_id = ?1 AND consumed_at IS NULL ORDER BY name, key",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| fact_view_from_row(r)).collect())
    }

    fn list_facts_including_consumed(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        let rows = self
            .sql
            .query(
                "SELECT fact_id, program_version_id, revision_epoch, name, key, value_json, \
                 provenance_class, source_span_json, source_event_id FROM facts \
                 WHERE instance_id = ?1 ORDER BY name, key",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| fact_view_from_row(r)).collect())
    }

    fn list_effects(&self, instance_id: &str) -> StoreResult<Vec<EffectView>> {
        let rows = self
            .sql
            .query(
                "SELECT effects.effect_id, effects.kind, effects.target, effects.input_json, \
                 effects.status, effects.created_by_rule, effects.program_version_id, \
                 effects.revision_epoch, effects.profile, effects.required_capabilities, \
                 effects.policy_block_reason, effects.policy_block_category, \
                 COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]'), \
                 EXISTS (SELECT 1 FROM effect_cancellation_requests AS request \
                 WHERE request.instance_id = effects.instance_id \
                 AND request.effect_id = effects.effect_id AND request.status = 'requested'), \
                 effects.created_by_event_id \
                 FROM effects \
                 LEFT JOIN instances ON instances.instance_id = effects.instance_id \
                 LEFT JOIN program_versions AS active_versions \
                 ON active_versions.version_id = instances.version_id \
                 LEFT JOIN program_versions AS effect_versions \
                 ON effect_versions.version_id = effects.program_version_id \
                 WHERE effects.instance_id = ?1 ORDER BY effects.created_at, effects.effect_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        // RC-4b on the effects plane (parity with native list_effects).
        let live = do_live_event_ids(&self.sql, instance_id)?;
        Ok(rows
            .iter()
            .filter(|row| match (&live, &row.get(14).map(as_opt_text)) {
                (Some(live), Some(Some(event_id))) => live.contains(event_id),
                _ => true,
            })
            .map(|r| effect_view_from_row(r))
            .collect())
    }

    fn list_runs(&self, instance_id: &str) -> StoreResult<Vec<RunView>> {
        let rows = self
            .sql
            .query(
                "SELECT run_id, effect_id, provider, worker_id, status, started_at, \
                 completed_at, metadata_json, \
                 EXISTS (SELECT 1 FROM effect_cancellation_requests AS request \
                 WHERE request.instance_id = runs.instance_id \
                 AND request.effect_id = runs.effect_id AND request.status = 'requested') \
                 FROM runs WHERE runs.instance_id = ?1 ORDER BY started_at, run_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| run_view_from_row(r)).collect())
    }

    fn status(&self, instance_id: &str) -> StoreResult<Option<StatusView>> {
        let Some(instance) = self.get_instance(instance_id)? else {
            return Ok(None);
        };
        // COUNT(*) over `table` scoped to the instance, with an optional predicate —
        // mirrors the native `count_where` helper.
        let count_where = |table: &str, predicate: Option<&str>| -> StoreResult<i64> {
            let mut sql = format!("SELECT COUNT(*) FROM {table} WHERE instance_id = ?1");
            if let Some(predicate) = predicate {
                sql.push_str(" AND ");
                sql.push_str(predicate);
            }
            let rows = self
                .sql
                .query(&sql, &[text(instance_id)])
                .map_err(sql_err)?;
            Ok(rows.first().map(|r| as_i64(&r[0])).unwrap_or(0))
        };

        let fact_count = count_where("facts", None)?;
        let queued_effect_count = count_where(
            "effects",
            Some("status IN ('queued', 'blocked_by_dependency')"),
        )?;
        let blocked_effect_count = count_where(
            "effects",
            Some(
                "status IN ('blocked_by_capability', 'blocked_by_profile', 'blocked_by_capacity')",
            ),
        )?;
        let active_run_count = count_where("runs", Some("status = 'running'"))?;
        let failure_count = count_where("effects", Some("status IN ('failed', 'timed_out')"))?;
        let cancellation_request_count =
            count_where("effect_cancellation_requests", Some("status = 'requested'"))?;
        let mut recent_events = self.list_events(instance_id)?;
        if recent_events.len() > 5 {
            recent_events = recent_events.split_off(recent_events.len() - 5);
        }
        let revisions = self.list_instance_revisions(instance_id)?;
        let parent_invocation = self.get_parent_workflow_invocation(instance_id)?;
        let child_invocations = self.list_child_workflow_invocations(instance_id)?;

        Ok(Some(StatusView {
            instance,
            fact_count,
            queued_effect_count,
            blocked_effect_count,
            active_run_count,
            failure_count,
            cancellation_request_count,
            revisions,
            parent_invocation,
            child_invocations,
            recent_events,
        }))
    }

    fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize> {
        do_satisfy_dependencies(&self.sql, instance_id)
    }

    fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent> {
        // A host reattachment after `NeedsIo` re-enters the exact running
        // effect with the same deterministic run/lease ids. Treat that as the
        // same run, not a second claim. Any identity drift fails closed.
        let existing = self
            .sql
            .query(
                "SELECT runs.effect_id, runs.instance_id, runs.provider, runs.worker_id, \
                 runs.status, leases.lease_id, leases.status \
                 FROM runs JOIN leases ON leases.run_id = runs.run_id \
                 WHERE runs.run_id = ?1 LIMIT 1",
                &[text(run.run_id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = existing.first() {
            let matches = as_text(&row[0]) == run.effect_id
                && as_text(&row[1]) == run.instance_id
                && as_text(&row[2]) == run.provider
                && as_text(&row[3]) == run.worker_id
                && as_text(&row[4]) == "running"
                && as_text(&row[5]) == run.lease_id
                && as_text(&row[6]) == "active";
            if !matches {
                return Err(StoreError::Conflict(
                    "run id was reused with different active run identity".to_owned(),
                ));
            }
            return self
                .event_by_idempotency_key(run.instance_id, run.run_id)?
                .ok_or_else(|| {
                    StoreError::Conflict("active run has no durable run-start event".to_owned())
                });
        }
        let status_rows = self
            .sql
            .query(
                "SELECT status FROM instances WHERE instance_id = ?1",
                &[text(run.instance_id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = status_rows.first() {
            let status = as_text(&row[0]);
            if status != "running" {
                return Err(StoreError::Conflict(format!(
                    "instance is {status}; provider runs require a running instance"
                )));
            }
        }
        if let Some(block) = do_policy_block(&self.sql, run.instance_id, run.effect_id)? {
            let payload = serde_json::json!({
                "effect_id": run.effect_id,
                "status": block.status,
                "reason": block.reason,
            })
            .to_string();
            do_append_event(
                &self.sql,
                NewEvent {
                    instance_id: run.instance_id,
                    event_type: "effect.blocked",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(run.effect_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!(
                        "policy-block:{}:{}",
                        run.effect_id, run.run_id
                    )),
                },
            )?;
            self.sql
                .execute(
                    "UPDATE effects SET status = ?1, policy_block_reason = ?2, \
                     updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?3 AND effect_id = ?4 \
                     AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')",
                    &[
                        text(block.status),
                        text(&block.reason),
                        text(run.instance_id),
                        text(run.effect_id),
                    ],
                )
                .map_err(sql_err)?;
            return Err(StoreError::PolicyBlocked {
                effect_id: run.effect_id.to_owned(),
                reason: block.reason,
            });
        }
        // Dependency gate: NOT EXISTS an unsatisfied dependency.
        let claimable_rows = self
            .sql
            .query(
                "SELECT NOT EXISTS (SELECT 1 FROM effect_dependencies AS dependency \
                 JOIN effects AS upstream ON upstream.effect_id = dependency.upstream_effect_id \
                  AND upstream.instance_id = dependency.instance_id \
                 WHERE dependency.instance_id = ?1 AND dependency.downstream_effect_id = ?2 \
                 AND NOT ( \
                   (dependency.predicate = 'succeeds' AND upstream.status = 'completed') \
                   OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out')) \
                   OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out') \
                   OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled') \
                   OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled')) \
                 ))",
                &[text(run.instance_id), text(run.effect_id)],
            )
            .map_err(sql_err)?;
        let claimable = claimable_rows
            .first()
            .map(|r| as_i64(&r[0]) != 0)
            .unwrap_or(true);
        if !claimable {
            self.sql
                .execute(
                    "UPDATE effects SET status = 'blocked_by_dependency', \
                     updated_at = CURRENT_TIMESTAMP \
                     WHERE instance_id = ?1 AND effect_id = ?2 AND status = 'queued'",
                    &[text(run.instance_id), text(run.effect_id)],
                )
                .map_err(sql_err)?;
            return Err(StoreError::Conflict(
                "effect dependencies are not satisfied".to_owned(),
            ));
        }
        if self.effect_has_open_cancellation_request(run.instance_id, run.effect_id)? {
            return Err(StoreError::Conflict(
                "effect cancellation has been requested".to_owned(),
            ));
        }
        if let Some(reason) = do_capacity_block(&self.sql, run.instance_id, run.effect_id)? {
            let payload = serde_json::json!({
                "effect_id": run.effect_id,
                "status": "blocked_by_capacity",
                "reason": reason,
            })
            .to_string();
            // Idempotent: the same (effect, run) can be capacity-blocked again
            // on a later worker pass after an interleaved unblock — the same
            // durable statement, not a second event.
            do_append_event_idempotent(
                &self.sql,
                NewEvent {
                    instance_id: run.instance_id,
                    event_type: "effect.blocked",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(run.effect_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!(
                        "capacity-block:{}:{}",
                        run.effect_id, run.run_id
                    )),
                },
            )?;
            self.sql
                .execute(
                    "UPDATE effects SET status = 'blocked_by_capacity', policy_block_reason = ?1, \
                     updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?2 AND effect_id = ?3 \
                     AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity')",
                    &[text(&reason), text(run.instance_id), text(run.effect_id)],
                )
                .map_err(sql_err)?;
            return Err(StoreError::CapacityBlocked {
                effect_id: run.effect_id.to_owned(),
                reason,
            });
        }

        let fingerprint = do_execution_fingerprint(&self.sql, run.instance_id, run.effect_id)?;
        let run_metadata = inject_execution_fingerprint(&run, run.metadata_json, &fingerprint)?;
        let payload = run_start_payload(&run, &run_metadata)?;
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: run.instance_id,
                event_type: "effect.run_started",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(run.effect_id),
                correlation_id: None,
                idempotency_key: Some(run.run_id),
            },
        )?;
        let changed = self
            .sql
            .execute(
                "UPDATE effects SET status = 'running', policy_block_reason = NULL, \
                 policy_block_category = NULL, updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND effect_id = ?2 \
                 AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')",
                &[text(run.instance_id), text(run.effect_id)],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect is not claimable".to_owned()));
        }
        self.sql
            .execute(
                "INSERT INTO runs (run_id, effect_id, instance_id, provider, worker_id, status, \
                 metadata_json) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6)",
                &[
                    text(run.run_id),
                    text(run.effect_id),
                    text(run.instance_id),
                    text(run.provider),
                    text(run.worker_id),
                    text(&run_metadata),
                ],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "INSERT INTO leases (lease_id, run_id, effect_id, instance_id, worker_id, status, \
                 expires_at) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)",
                &[
                    text(run.lease_id),
                    text(run.run_id),
                    text(run.effect_id),
                    text(run.instance_id),
                    text(run.worker_id),
                    text(run.lease_expires_at),
                ],
            )
            .map_err(sql_err)?;
        Ok(event)
    }

    fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent> {
        let current = self
            .sql
            .query(
                "SELECT status, policy_block_category FROM effects \
                 WHERE instance_id = ?1 AND effect_id = ?2",
                &[text(instance_id), text(effect_id)],
            )
            .map_err(sql_err)?;
        let already_blocked = current.first().is_some_and(|r| {
            as_text(&r[0]) == "blocked" && as_opt_text(&r[1]).as_deref() == Some(category)
        });
        if already_blocked {
            // Return the existing block event without recording a new one.
            let rows = self
                .sql
                .query(
                    "SELECT event_id, sequence FROM events \
                     WHERE instance_id = ?1 AND event_type = 'effect.blocked' AND causation_id = ?2 \
                     ORDER BY sequence DESC LIMIT 1",
                    &[text(instance_id), text(effect_id)],
                )
                .map_err(sql_err)?;
            let row = rows
                .first()
                .ok_or_else(|| sql_err("missing prior block event".to_string()))?;
            return Ok(StoredEvent {
                event_id: as_text(&row[0]),
                sequence: as_i64(&row[1]),
            });
        }
        let payload = serde_json::json!({
            "effect_id": effect_id,
            "status": "blocked",
            "category": category,
            "reason": detail,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id,
                event_type: "effect.blocked",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key: Some(&format!(
                    "binding-block:{instance_id}:{effect_id}:{category}"
                )),
            },
        )?;
        self.sql
            .execute(
                "UPDATE effects SET status = 'blocked', policy_block_reason = ?1, \
                 policy_block_category = ?2, updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?3 AND effect_id = ?4 \
                 AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity')",
                &[text(detail), text(category), text(instance_id), text(effect_id)],
            )
            .map_err(sql_err)?;
        Ok(event)
    }

    fn transition_instance(
        &mut self,
        transition: InstanceTransition<'_>,
    ) -> StoreResult<StoredEvent> {
        fn transition_allowed(current: &str, next: &str) -> bool {
            matches!(
                (current, next),
                ("running", "paused")
                    | ("paused", "running")
                    | ("running", "cancelled")
                    | ("paused", "cancelled")
                    | ("blocked", "cancelled")
                    | ("running", "failed")
                    | ("paused", "failed")
                    | ("blocked", "failed")
            )
        }

        let current_rows = self
            .sql
            .query(
                "SELECT status FROM instances WHERE instance_id = ?1",
                &[text(transition.instance_id)],
            )
            .map_err(sql_err)?;
        let current_status = current_rows
            .first()
            .map(|r| as_text(&r[0]))
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        if !transition_allowed(&current_status, transition.status) {
            return Err(StoreError::Conflict(format!(
                "cannot transition instance from {current_status} to {}",
                transition.status
            )));
        }
        let payload = serde_json::json!({
            "instance_id": transition.instance_id,
            "status": transition.status,
            "reason": transition.reason,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: transition.instance_id,
                event_type: "instance.transitioned",
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: transition.idempotency_key,
            },
        )?;
        self.sql
            .execute(
                "UPDATE instances SET status = ?1, last_event_id = ?2, last_error = ?3, \
                 updated_at = CURRENT_TIMESTAMP, completed_at = CASE \
                 WHEN ?1 IN ('completed', 'cancelled', 'failed') THEN CURRENT_TIMESTAMP \
                 ELSE completed_at END WHERE instance_id = ?4",
                &[
                    text(transition.status),
                    text(&event.event_id),
                    opt_text(transition.reason),
                    text(transition.instance_id),
                ],
            )
            .map_err(sql_err)?;
        Ok(event)
    }

    fn due_time_effects(&self, instance_id: &str, now: &str) -> StoreResult<Vec<DueTimeEffect>> {
        let rows = self
            .sql
            .query(
                "SELECT candidate.effect_id, candidate.kind, candidate.status, \
                 COALESCE(candidate.timeout_seconds, 0) FROM effects AS candidate \
                 WHERE candidate.instance_id = ?1 \
                 AND candidate.status NOT IN ('completed', 'failed', 'timed_out', 'cancelled') \
                 AND ( \
                   (candidate.timeout_seconds IS NOT NULL \
                    AND (strftime('%s', ?2) - strftime('%s', candidate.created_at)) \
                        >= candidate.timeout_seconds) \
                   OR (json_extract(candidate.input_json, '$.deadline_at') IS NOT NULL \
                       AND CAST(strftime('%s', ?2) AS INTEGER) \
                           >= CAST(strftime('%s', json_extract(candidate.input_json, \
                              '$.deadline_at')) AS INTEGER)) \
                 ) AND ( \
                   candidate.kind != 'timer.wait' OR NOT EXISTS ( \
                     SELECT 1 FROM effect_dependencies AS dependency \
                     JOIN effects AS upstream ON upstream.effect_id = dependency.upstream_effect_id \
                      AND upstream.instance_id = dependency.instance_id \
                     WHERE dependency.instance_id = candidate.instance_id \
                       AND dependency.downstream_effect_id = candidate.effect_id AND NOT ( \
                         (dependency.predicate = 'succeeds' AND upstream.status = 'completed') \
                         OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out')) \
                         OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out') \
                         OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled') \
                         OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled')) \
                       ) \
                   ) \
                 ) ORDER BY candidate.created_at, candidate.effect_id",
                &[text(instance_id), text(now)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| due_time_effect_from_row(r)).collect())
    }

    fn due_interval_occurrences(
        &self,
        after_scheduled: &str,
        interval_seconds: i64,
        now: &str,
    ) -> StoreResult<Vec<String>> {
        if interval_seconds <= 0 {
            return Ok(Vec::new());
        }
        let rows = self
            .sql
            .query(
                "WITH RECURSIVE occurrence(scheduled_epoch) AS ( \
                   SELECT CAST(strftime('%s', ?1) AS INTEGER) + ?2 \
                   UNION ALL SELECT scheduled_epoch + ?2 FROM occurrence \
                   WHERE scheduled_epoch + ?2 <= CAST(strftime('%s', ?3) AS INTEGER) \
                     AND scheduled_epoch < CAST(strftime('%s', ?1) AS INTEGER) + (?2 * 100000) \
                 ) SELECT strftime('%Y-%m-%dT%H:%M:%SZ', scheduled_epoch, 'unixepoch') \
                 FROM occurrence WHERE scheduled_epoch <= CAST(strftime('%s', ?3) AS INTEGER) \
                 ORDER BY scheduled_epoch",
                &[text(after_scheduled), int(interval_seconds), text(now)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| as_text(&r[0])).collect())
    }

    fn resolve_clock(&self, now: &str) -> StoreResult<String> {
        let rows = self
            .sql
            .query("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?1)", &[text(now)])
            .map_err(sql_err)?;
        rows.first()
            .and_then(|r| as_opt_text(&r[0]))
            .ok_or_else(|| StoreError::Conflict(format!("unparseable clock instant `{now}`")))
    }

    fn last_clock_occurrence(
        &self,
        instance_id: &str,
        signal: &str,
    ) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT MAX(json_extract(payload_json, '$.scheduled_at')) FROM events \
                 WHERE instance_id = ?1 AND event_type = ?2",
                &[text(instance_id), text(signal)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().and_then(|r| as_opt_text(&r[0])))
    }

    fn pending_time_effects(&self, instance_id: &str) -> StoreResult<Vec<DueTimeEffect>> {
        let rows = self
            .sql
            .query(
                "SELECT effect_id, kind, status, timeout_seconds FROM effects \
                 WHERE instance_id = ?1 AND timeout_seconds IS NOT NULL \
                 AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled') \
                 ORDER BY created_at, effect_id",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|r| due_time_effect_from_row(r)).collect())
    }

    fn expire_effect(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "effect_id": effect_id,
            "status": "timed_out",
            "reason": "deadline exceeded",
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key,
            },
        )?;
        let changed = self
            .sql
            .execute(
                "UPDATE effects SET status = 'timed_out', updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND effect_id = ?2 \
                 AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')",
                &[text(instance_id), text(effect_id)],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect cannot expire".to_owned()));
        }
        Ok(event)
    }

    fn retire_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.sql
            .execute(
                "UPDATE facts SET consumed_at = CURRENT_TIMESTAMP, \
                 updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND fact_id = ?2 AND consumed_at IS NULL",
                &[text(instance_id), text(fact_id)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn revive_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.sql
            .execute(
                "UPDATE facts SET consumed_at = NULL, updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND fact_id = ?2 AND consumed_at IS NOT NULL",
                &[text(instance_id), text(fact_id)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn cancel_effect(&mut self, cancellation: EffectCancellation<'_>) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "effect_id": cancellation.effect_id,
            "status": "cancelled",
            "reason": cancellation.reason,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: cancellation.instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(cancellation.effect_id),
                correlation_id: None,
                idempotency_key: cancellation.idempotency_key,
            },
        )?;
        let changed = self
            .sql
            .execute(
                "UPDATE effects SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND effect_id = ?2 \
                 AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')",
                &[text(cancellation.instance_id), text(cancellation.effect_id)],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "effect cannot be cancelled".to_owned(),
            ));
        }
        do_mark_cancellation_requests_terminal(
            &self.sql,
            cancellation.instance_id,
            cancellation.effect_id,
            &event.event_id,
        )?;
        self.satisfy_dependencies(cancellation.instance_id)?;
        Ok(event)
    }

    fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "lease_id": renewal.lease_id,
            "run_id": renewal.run_id,
            "new_expires_at": renewal.new_expires_at,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: renewal.instance_id,
                event_type: "lease.renewed",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(renewal.run_id),
                correlation_id: None,
                idempotency_key: renewal.idempotency_key,
            },
        )?;
        let changed = self
            .sql
            .execute(
                "UPDATE leases SET expires_at = ?1 WHERE instance_id = ?2 AND lease_id = ?3 \
                 AND run_id = ?4 AND status = 'active'",
                &[
                    text(renewal.new_expires_at),
                    text(renewal.instance_id),
                    text(renewal.lease_id),
                    text(renewal.run_id),
                ],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict("lease cannot be renewed".to_owned()));
        }
        Ok(event)
    }

    fn expire_leases(&mut self, instance_id: &str, now: &str) -> StoreResult<Vec<ExpiredLease>> {
        let rows = self
            .sql
            .query(
                "SELECT lease_id, run_id, effect_id FROM leases \
                 WHERE instance_id = ?1 AND status = 'active' AND expires_at <= ?2 \
                 ORDER BY expires_at, lease_id",
                &[text(instance_id), text(now)],
            )
            .map_err(sql_err)?;
        let expired: Vec<ExpiredLease> = rows
            .iter()
            .map(|r| ExpiredLease {
                lease_id: as_text(&r[0]),
                run_id: as_text(&r[1]),
                effect_id: as_text(&r[2]),
            })
            .collect();
        for lease in &expired {
            let payload = serde_json::json!({
                "lease_id": lease.lease_id,
                "run_id": lease.run_id,
                "effect_id": lease.effect_id,
                "expired_at": now,
            })
            .to_string();
            do_append_event(
                &self.sql,
                NewEvent {
                    instance_id,
                    event_type: "lease.expired",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(&lease.run_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!("lease-expired:{}", lease.lease_id)),
                },
            )?;
            self.sql
                .execute(
                    "UPDATE leases SET status = 'expired', released_at = CURRENT_TIMESTAMP \
                     WHERE lease_id = ?1",
                    &[text(&lease.lease_id)],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "UPDATE runs SET status = 'lease_expired', completed_at = CURRENT_TIMESTAMP \
                     WHERE run_id = ?1 AND status = 'running'",
                    &[text(&lease.run_id)],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "UPDATE effects SET status = 'queued', updated_at = CURRENT_TIMESTAMP \
                     WHERE instance_id = ?1 AND effect_id = ?2 AND status = 'running'",
                    &[text(instance_id), text(&lease.effect_id)],
                )
                .map_err(sql_err)?;
        }
        Ok(expired)
    }

    fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent> {
        let payload = serde_json::json!({
            "effect_id": retry.effect_id,
            "retry_after": retry.retry_after,
        })
        .to_string();
        let event = do_append_event(
            &self.sql,
            NewEvent {
                instance_id: retry.instance_id,
                event_type: "effect.retried",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(retry.effect_id),
                correlation_id: None,
                idempotency_key: retry.idempotency_key,
            },
        )?;
        let changed = self
            .sql
            .execute(
                "UPDATE effects SET status = 'queued', updated_at = CURRENT_TIMESTAMP \
                 WHERE instance_id = ?1 AND effect_id = ?2 AND status IN ('failed', 'timed_out')",
                &[text(retry.instance_id), text(retry.effect_id)],
            )
            .map_err(sql_err)?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect is not retryable".to_owned()));
        }
        Ok(event)
    }

    fn rebuild_projections(&mut self, instance_id: &str) -> StoreResult<()> {
        self.rebuild_projections_impl(instance_id, None)
    }

    fn table_exists(&self, table: &str) -> StoreResult<bool> {
        let rows = self
            .sql
            .query(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                &[text(table)],
            )
            .map_err(sql_err)?;
        Ok(!rows.is_empty())
    }
}

// -- WorkItems over DoSql (event-sourced; ADR-0002 v1) ----------------------
//
// The builtin work-item tracker (`spec/work-queues.md`) rebuilt as an
// event-sourced provider on the DO's one SQLite, so the DO backs the
// `WorkItems` surface the rule pass reaches (`project_tracker_issues` /
// holder-release) the same way it backs `RuntimeStore`. This is the exact same
// event/projection/lease model as the native `WorkItemStore` (append-only
// `tracker_events` = source of truth; `tracker_issues` / `tracker_relations` /
// `tracker_leases` = disposable projections; claims are runtime leases split
// from durable status). The native SQL used a rusqlite `Immediate` transaction
// for the claim CAS; the DO's single-writer per-invocation model supplies that
// atomicity (these methods never yield mid-sequence), so the check-then-insert
// claim is exclusive without an explicit transaction — the same argument as the
// RuntimeStore port.

const DO_ISSUE_COLS: &str = "issue_id, queue, title, body, status, labels_json, \
     metadata_json, assigned_to, filed_by, created_at, updated_at";

/// The active-lease predicate over `tracker_leases`, with the clock inlined as
/// `datetime('now')`. A NULL `expires_at` models a lease with no TTL.
const DO_ACTIVE_LEASE: &str =
    "released_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))";

/// Map a positional `tracker_issues` row to a `WorkItem` (column order =
/// `DO_ISSUE_COLS`). `claimed_by` is supplied by the lease overlay, not the
/// durable projection.
fn do_issue_row(row: &[SqlValue]) -> WorkItem {
    WorkItem {
        id: as_text(&row[0]),
        queue: as_text(&row[1]),
        title: as_text(&row[2]),
        body: as_text(&row[3]),
        status: as_text(&row[4]),
        labels: serde_json::from_str(&as_text(&row[5])).unwrap_or_default(),
        metadata: serde_json::from_str(&as_text(&row[6])).unwrap_or_else(|_| serde_json::json!({})),
        claimed_by: None,
        assigned_to: as_opt_text(&row[7]),
        filed_by: as_opt_text(&row[8]),
        created_at: as_text(&row[9]),
        updated_at: as_text(&row[10]),
    }
}

/// Capture a single now-timestamp for one op; every event + projection field it
/// derives uses this, so a rebuild reproduces the same values.
fn do_now(sql: &impl DoSql) -> StoreResult<String> {
    let rows = sql.query("SELECT datetime('now')", &[]).map_err(sql_err)?;
    Ok(rows
        .first()
        .map_or_else(String::new, |row| as_text(&row[0])))
}

/// Resolve a human `WS-N` alias to its opaque `content_id` merge identity
/// (ADR-0002 phase B1: the DO event log is keyed by content_id, like native).
fn do_content_id(sql: &impl DoSql, alias: &str) -> StoreResult<Option<String>> {
    let rows = sql
        .query(
            "SELECT content_id FROM tracker_aliases WHERE alias = ?1",
            &[text(alias)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| as_text(&row[0])))
}

/// The issue's current head event ids — events nothing lists as a parent.
fn do_issue_heads(sql: &impl DoSql, content_id: &str) -> StoreResult<Vec<String>> {
    let rows = sql
        .query(
            "SELECT e.event_id FROM tracker_events e \
             WHERE e.issue_id = ?1 AND e.event_id IS NOT NULL \
               AND NOT EXISTS ( \
                 SELECT 1 FROM tracker_events c \
                 WHERE c.issue_id = ?1 \
                   AND instr(c.parents_json, '\"' || e.event_id || '\"') > 0)",
            &[text(content_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.iter().map(|row| as_text(&row[0])).collect())
}

/// Append one immutable content-addressed tracker event (INSERT only), keyed by
/// the issue's opaque content_id. `event_id_override` is used only for the
/// `issue.created` root (whose id IS the content_id). Deduped by `event_id`.
fn do_tracker_append_raw(
    sql: &impl DoSql,
    content_id: Option<&str>,
    event_id_override: Option<&str>,
    kind: &str,
    payload_json: &str,
    actor: Option<&str>,
    now: &str,
) -> StoreResult<String> {
    let parents = match content_id {
        Some(id) => do_issue_heads(sql, id)?,
        None => Vec::new(),
    };
    let event_id = match event_id_override {
        Some(id) => id.to_owned(),
        None => whipplescript_store::items::event_content_id(
            kind,
            content_id,
            payload_json,
            actor,
            &parents,
            now,
        ),
    };
    let parents_json =
        serde_json::to_string(&parents).map_err(|error| sql_err(error.to_string()))?;
    sql.execute(
        "INSERT OR IGNORE INTO tracker_events \
         (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &[
            text(&event_id),
            text(&parents_json),
            opt_text(content_id),
            text(kind),
            text(payload_json),
            opt_text(actor),
            text(now),
        ],
    )
    .map_err(sql_err)?;
    Ok(event_id)
}

/// Append one event for an issue given by its `WS-N` alias — resolves the alias
/// to the opaque content_id the event log is keyed by (merge-stable).
fn do_tracker_append(
    sql: &impl DoSql,
    alias: Option<&str>,
    kind: &str,
    payload: &serde_json::Value,
    actor: Option<&str>,
    now: &str,
) -> StoreResult<()> {
    let content_id = match alias {
        Some(a) => Some(
            do_content_id(sql, a)?
                .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {a}")))?,
        ),
        None => None,
    };
    do_tracker_append_raw(
        sql,
        content_id.as_deref(),
        None,
        kind,
        &payload.to_string(),
        actor,
        now,
    )?;
    Ok(())
}

/// Load one issue's events (by content_id) into the shared `IssueEvent` shape
/// for `analyze_issue_dag` — the DO store shares the native conflict analysis.
fn do_load_issue_events(
    sql: &impl DoSql,
    content_id: &str,
) -> StoreResult<Vec<whipplescript_store::items::IssueEvent>> {
    let rows = sql
        .query(
            "SELECT event_id, parents_json, kind, payload_json FROM tracker_events \
             WHERE issue_id = ?1 ORDER BY event_seq",
            &[text(content_id)],
        )
        .map_err(sql_err)?;
    Ok(rows
        .iter()
        .map(|row| whipplescript_store::items::IssueEvent {
            event_id: as_opt_text(&row[0]).unwrap_or_default(),
            parents: serde_json::from_str(&as_text(&row[1])).unwrap_or_default(),
            kind: as_text(&row[2]),
            payload: serde_json::from_str(&as_text(&row[3]))
                .unwrap_or_else(|_| serde_json::json!({})),
        })
        .collect())
}

/// The holder of the active lease on an issue, if any.
fn do_active_holder(sql: &impl DoSql, item_id: &str) -> StoreResult<Option<String>> {
    let rows = sql
        .query(
            &format!(
                "SELECT actor FROM tracker_leases WHERE issue_id = ?1 AND {DO_ACTIVE_LEASE} \
                 ORDER BY acquired_at DESC LIMIT 1"
            ),
            &[text(item_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| as_text(&row[0])))
}

/// All active leases as an `issue_id -> holder` map (for the list overlay).
fn do_active_holders(sql: &impl DoSql) -> StoreResult<std::collections::HashMap<String, String>> {
    let rows = sql
        .query(
            &format!("SELECT issue_id, actor FROM tracker_leases WHERE {DO_ACTIVE_LEASE}"),
            &[],
        )
        .map_err(sql_err)?;
    Ok(rows
        .iter()
        .map(|row| (as_text(&row[0]), as_text(&row[1])))
        .collect())
}

/// Lazily expire past-due, still-held leases on an issue, so an expired lease
/// frees the issue for a fresh claim.
fn do_expire_stale_leases(sql: &impl DoSql, item_id: &str, now: &str) -> StoreResult<()> {
    let stale = sql
        .query(
            "SELECT lease_id FROM tracker_leases \
             WHERE issue_id = ?1 AND released_at IS NULL AND expires_at IS NOT NULL \
               AND expires_at <= ?2",
            &[text(item_id), text(now)],
        )
        .map_err(sql_err)?;
    for row in &stale {
        let lease_id = as_text(&row[0]);
        do_mark_lease_released(sql, &lease_id, item_id, "claim.expired", "system", now)?;
    }
    Ok(())
}

/// Release the (single) active lease on an issue, if present.
fn do_release_active_lease(sql: &impl DoSql, item_id: &str, now: &str) -> StoreResult<bool> {
    let rows = sql
        .query(
            &format!(
                "SELECT lease_id, actor FROM tracker_leases WHERE issue_id = ?1 AND {DO_ACTIVE_LEASE} \
                 ORDER BY acquired_at DESC LIMIT 1"
            ),
            &[text(item_id)],
        )
        .map_err(sql_err)?;
    match rows.first() {
        None => Ok(false),
        Some(row) => {
            let lease_id = as_text(&row[0]);
            let actor = as_text(&row[1]);
            do_mark_lease_released(sql, &lease_id, item_id, "claim.released", &actor, now)?;
            Ok(true)
        }
    }
}

/// Append a lease-terminal event and fold it into the lease projection.
fn do_mark_lease_released(
    sql: &impl DoSql,
    lease_id: &str,
    item_id: &str,
    kind: &str,
    actor: &str,
    now: &str,
) -> StoreResult<()> {
    let payload = serde_json::json!({"lease_id": lease_id, "actor": actor, "released_at": now});
    do_tracker_append(sql, Some(item_id), kind, &payload, Some(actor), now)?;
    sql.execute(
        "UPDATE tracker_leases SET released_at = ?2 WHERE lease_id = ?1",
        &[text(lease_id), text(now)],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// The restore-marker fold over the EFFECTS plane (DO parity of the
/// native `live_event_ids_on`): `None` when no `context.restored` marker
/// exists (the fast path filters nothing).
fn do_live_event_ids<S: DoSql>(
    sql: &S,
    instance_id: &str,
) -> StoreResult<Option<std::collections::BTreeSet<String>>> {
    let rows = sql
        .query(
            "SELECT event_id, sequence, event_type, payload_json FROM events \
             WHERE instance_id = ?1 ORDER BY sequence",
            &[text(instance_id)],
        )
        .map_err(sql_err)?;
    let mut saw_marker = false;
    let mut live: Vec<(String, i64)> = Vec::new();
    for row in &rows {
        let event_type = as_text(&row[2]);
        if event_type == "context.restored" {
            saw_marker = true;
            if let Some(target) = serde_json::from_str::<serde_json::Value>(&as_text(&row[3]))
                .ok()
                .and_then(|payload| payload.get("restored_to_sequence")?.as_i64())
            {
                live.retain(|(_, seq)| *seq <= target);
            }
        }
        live.push((as_text(&row[0]), as_i64(&row[1])));
    }
    if !saw_marker {
        return Ok(None);
    }
    Ok(Some(
        live.into_iter().map(|(event_id, _)| event_id).collect(),
    ))
}

impl<Sql: DoSql> WorkItems for DoSqliteStore<Sql> {
    fn event_position(&self) -> StoreResult<i64> {
        let rows = self
            .sql
            .query(
                "SELECT COALESCE(MAX(event_seq), 0) FROM tracker_events",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_i64(&row[0])).unwrap_or(0))
    }

    fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &serde_json::Value,
        filed_by: Option<&str>,
    ) -> StoreResult<WorkItem> {
        let now = do_now(&self.sql)?;
        // Mint the next sequential id (`WS-1`, `WS-2`, …); single-writer per
        // invocation makes the counter bump + append + project atomic.
        let bumped = self
            .sql
            .query(
                "UPDATE tracker_counter SET next_id = next_id + 1 WHERE singleton = 1 \
                 RETURNING next_id - 1",
                &[],
            )
            .map_err(sql_err)?;
        let next = bumped
            .first()
            .map(|row| as_i64(&row[0]))
            .ok_or_else(|| StoreError::Conflict("tracker_counter row missing".to_owned()))?;
        let item_id = format!("WS-{next}");
        let labels_json =
            serde_json::to_string(labels).map_err(|error| sql_err(error.to_string()))?;
        let payload = serde_json::json!({
            "queue": queue,
            "title": title,
            "body": body,
            "labels": labels,
            "metadata": metadata,
            "filed_by": filed_by,
        });
        // Opaque merge identity = the content-hash of the creation event; WS-N
        // is only a local alias for it. The event log is keyed by content_id.
        let payload_json = payload.to_string();
        let content_id = whipplescript_store::items::event_content_id(
            "issue.created",
            None,
            &payload_json,
            filed_by,
            &[],
            &now,
        );
        self.sql
            .execute(
                "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
                &[text(&content_id), text(&item_id)],
            )
            .map_err(sql_err)?;
        do_tracker_append_raw(
            &self.sql,
            Some(&content_id),
            Some(&content_id),
            "issue.created",
            &payload_json,
            filed_by,
            &now,
        )?;
        self.sql
            .execute(
                "INSERT INTO tracker_issues \
                 (issue_id, queue, title, body, status, labels_json, metadata_json, filed_by, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?8)",
                &[
                    text(&item_id),
                    text(queue),
                    text(title),
                    text(body),
                    text(&labels_json),
                    text(&metadata.to_string()),
                    opt_text(filed_by),
                    text(&now),
                ],
            )
            .map_err(sql_err)?;
        self.get_item(&item_id)?
            .ok_or_else(|| StoreError::Conflict("filed item missing".to_owned()))
    }

    fn get_item(&self, item_id: &str) -> StoreResult<Option<WorkItem>> {
        let rows = self
            .sql
            .query(
                &format!("SELECT {DO_ISSUE_COLS} FROM tracker_issues WHERE issue_id = ?1"),
                &[text(item_id)],
            )
            .map_err(sql_err)?;
        match rows.first() {
            None => Ok(None),
            Some(row) => {
                let holder = do_active_holder(&self.sql, item_id)?;
                Ok(Some(apply_overlay(do_issue_row(row), holder)))
            }
        }
    }

    fn list_items(&self, queue: Option<&str>, status: Option<&str>) -> StoreResult<Vec<WorkItem>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {DO_ISSUE_COLS} FROM tracker_issues \
                     WHERE (?1 IS NULL OR queue = ?1) ORDER BY created_at, issue_id"
                ),
                &[opt_text(queue)],
            )
            .map_err(sql_err)?;
        let holders = do_active_holders(&self.sql)?;
        // The overlay can turn a durable-`open` issue into effective
        // `in_progress`, so the status filter runs over the OVERLAID status.
        Ok(rows
            .iter()
            .map(|row| {
                let base = do_issue_row(row);
                let holder = holders.get(&base.id).cloned();
                apply_overlay(base, holder)
            })
            .filter(|item| status.is_none_or(|want| item.status == want))
            .collect())
    }

    fn ready_items(&self, queue: &str) -> StoreResult<Vec<WorkItem>> {
        // Ready iff durable `open`, no active lease, no active blocker (a
        // `blocks(B, id)` with B still open). Expired/released leases and
        // closed/canceled blockers do not gate.
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {DO_ISSUE_COLS} FROM tracker_issues i \
                     WHERE i.queue = ?1 AND i.status = 'open' \
                     AND NOT EXISTS ( \
                       SELECT 1 FROM tracker_leases l \
                       WHERE l.issue_id = i.issue_id \
                         AND l.released_at IS NULL \
                         AND (l.expires_at IS NULL OR l.expires_at > datetime('now'))) \
                     AND NOT EXISTS ( \
                       SELECT 1 FROM tracker_relations r JOIN tracker_issues b ON b.issue_id = r.from_issue \
                       WHERE r.to_issue = i.issue_id AND r.kind = 'blocks' AND b.status = 'open') \
                     ORDER BY i.created_at, i.issue_id"
                ),
                &[text(queue)],
            )
            .map_err(sql_err)?;
        // A conflicted issue is not ready (ADR-0002 phase B1 slice ii): its
        // field values are in dispute. Not expressible in the SQL predicate, so
        // filter here via the shared DAG conflict analysis.
        let mut ready = Vec::with_capacity(rows.len());
        for row in &rows {
            let item = do_issue_row(row);
            let conflicted = match do_content_id(&self.sql, &item.id)? {
                Some(content_id) => whipplescript_store::items::analyze_issue_dag(
                    &do_load_issue_events(&self.sql, &content_id)?,
                )
                .conflicted(),
                None => false,
            };
            if !conflicted {
                ready.push(item);
            }
        }
        // Ready rows have no active lease by construction; the overlay is a no-op.
        Ok(ready)
    }

    fn claim_item(
        &mut self,
        item_id: &str,
        claimed_by: &str,
        expires: Option<&str>,
    ) -> StoreResult<ClaimOutcome> {
        let now = do_now(&self.sql)?;
        let exists = !self
            .sql
            .query(
                "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
                &[text(item_id)],
            )
            .map_err(sql_err)?
            .is_empty();
        if !exists {
            return Ok(ClaimOutcome::NotFound);
        }
        do_expire_stale_leases(&self.sql, item_id, &now)?;
        // Exclusivity (tracker-lease I1): grant only when no active lease. The
        // single-writer invocation serializes this check-then-insert.
        if let Some(holder) = do_active_holder(&self.sql, item_id)? {
            return Ok(ClaimOutcome::AlreadyClaimed { holder });
        }
        // The lease's identity IS its `claim.acquired` event (content hash) —
        // merge-stable across clones, matching the native store.
        let content_id = do_content_id(&self.sql, item_id)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {item_id}")))?;
        // `expires` is an absolute deadline (`None` = no TTL); it records a
        // claim-TTL lease that `ready`/`claim` lazily reclaim once past-due.
        let payload = serde_json::json!({"actor": claimed_by, "expires_at": expires});
        let lease_id = do_tracker_append_raw(
            &self.sql,
            Some(&content_id),
            None,
            "claim.acquired",
            &payload.to_string(),
            Some(claimed_by),
            &now,
        )?;
        self.sql
            .execute(
                "INSERT INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                &[
                    text(&lease_id),
                    text(item_id),
                    text(claimed_by),
                    text(&now),
                    opt_text(expires),
                ],
            )
            .map_err(sql_err)?;
        Ok(ClaimOutcome::Claimed)
    }

    fn renew_claim(
        &mut self,
        item_id: &str,
        actor: &str,
        expires: Option<&str>,
    ) -> StoreResult<RenewOutcome> {
        let now = do_now(&self.sql)?;
        let rows = self
            .sql
            .query(
                "SELECT lease_id, expires_at FROM tracker_leases \
                 WHERE issue_id = ?1 AND actor = ?2 AND released_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?3)",
                &[text(item_id), text(actor), text(&now)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(RenewOutcome::NotHeld);
        };
        let lease_id = as_text(&row[0]);
        let current_expires = as_opt_text(&row[1]);
        // Monotonicity (tracker-lease I2): a finite deadline may not move back.
        if let (Some(want), Some(current)) = (expires, current_expires.as_deref()) {
            if want <= current {
                return Ok(RenewOutcome::NotMonotonic);
            }
        }
        let new_expires: Option<String> = match expires {
            Some(want) => Some(want.to_owned()),
            None => current_expires,
        };
        let payload =
            serde_json::json!({"lease_id": lease_id, "actor": actor, "expires_at": new_expires});
        do_tracker_append(
            &self.sql,
            Some(item_id),
            "claim.renewed",
            &payload,
            Some(actor),
            &now,
        )?;
        if expires.is_some() {
            self.sql
                .execute(
                    "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
                    &[text(&lease_id), opt_text(new_expires.as_deref())],
                )
                .map_err(sql_err)?;
        }
        Ok(RenewOutcome::Renewed {
            expires_at: new_expires,
        })
    }

    fn release_item(&mut self, item_id: &str) -> StoreResult<bool> {
        let now = do_now(&self.sql)?;
        do_release_active_lease(&self.sql, item_id, &now)
    }

    fn release_claims_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        // Terminal-releases-all (tracker-lease I3): every active lease the actor
        // holds across ALL issues is released in one invocation.
        let now = do_now(&self.sql)?;
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT lease_id, issue_id FROM tracker_leases WHERE actor = ?1 AND {DO_ACTIVE_LEASE}"
                ),
                &[text(holder)],
            )
            .map_err(sql_err)?;
        let leases: Vec<(String, String)> = rows
            .iter()
            .map(|row| (as_text(&row[0]), as_text(&row[1])))
            .collect();
        for (lease_id, issue_id) in &leases {
            do_mark_lease_released(
                &self.sql,
                lease_id,
                issue_id,
                "claim.released",
                holder,
                &now,
            )?;
        }
        Ok(leases.len())
    }

    fn finish_item(&mut self, item_id: &str, summary: Option<&str>) -> StoreResult<bool> {
        let now = do_now(&self.sql)?;
        let status = self
            .sql
            .query(
                "SELECT status FROM tracker_issues WHERE issue_id = ?1",
                &[text(item_id)],
            )
            .map_err(sql_err)?
            .first()
            .map(|row| as_text(&row[0]));
        if status.as_deref() != Some("open") {
            return Ok(false);
        }
        let payload = serde_json::json!({"status": "closed", "summary": summary});
        do_tracker_append(
            &self.sql,
            Some(item_id),
            "issue.closed",
            &payload,
            None,
            &now,
        )?;
        self.sql
            .execute(
                "UPDATE tracker_issues SET status = 'closed', claim_summary = ?2, updated_at = ?3 \
                 WHERE issue_id = ?1",
                &[text(item_id), opt_text(summary), text(&now)],
            )
            .map_err(sql_err)?;
        do_release_active_lease(&self.sql, item_id, &now)?;
        Ok(true)
    }

    fn add_blocks(&mut self, from: &str, to: &str) -> StoreResult<()> {
        self.add_relation(from, to, "blocks", None)
    }
}

// -- Phase-B tracker surface over DoSql (ADR-0002 B1/B2) --------------------
//
// The additive surface native `WorkItemStore` exposes as inherent methods,
// ported so the edge host is at parity: relation taxonomy, field sets +
// conflict view, comments/evidence, and merge (export/import). The DAG/hash
// core is shared from `whipplescript_store::items` — the DO only supplies the
// `DoSql` glue, so both backends mint identical event ids and detect conflicts
// identically.
impl<Sql: DoSql> DoSqliteStore<Sql> {
    /// Records a directed relation `kind(from -> to)`; only `blocks` gates
    /// readiness. `dep_kind` is valid only on `blocks`. Event payload carries
    /// content_ids (merge-stable); the projection keeps aliases.
    pub fn add_relation(
        &mut self,
        from: &str,
        to: &str,
        kind: &str,
        dep_kind: Option<&str>,
    ) -> StoreResult<()> {
        use whipplescript_store::items::{DEPENDENCY_KINDS, RELATION_KINDS};
        if !RELATION_KINDS.contains(&kind) {
            return Err(StoreError::Conflict(format!(
                "unknown relation kind `{kind}`"
            )));
        }
        if let Some(dk) = dep_kind {
            if kind != "blocks" {
                return Err(StoreError::Conflict(
                    "dep_kind only applies to `blocks` relations".to_owned(),
                ));
            }
            if !DEPENDENCY_KINDS.contains(&dk) {
                return Err(StoreError::Conflict(format!(
                    "unknown dependency kind `{dk}`"
                )));
            }
        }
        let now = do_now(&self.sql)?;
        let from_cid = do_content_id(&self.sql, from)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {from}")))?;
        let to_cid = do_content_id(&self.sql, to)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {to}")))?;
        let payload =
            serde_json::json!({"from": from_cid, "to": to_cid, "kind": kind, "dep_kind": dep_kind});
        do_tracker_append(&self.sql, Some(to), "relation.added", &payload, None, &now)?;
        self.sql
            .execute(
                "INSERT OR IGNORE INTO tracker_relations (from_issue, to_issue, kind, dep_kind) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[text(from), text(to), text(kind), opt_text(dep_kind)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// Sets one field of an issue (`issue.field_set`) — the mutation the conflict
    /// engine folds. Returns `false` if the issue is unknown.
    pub fn set_field(&mut self, item_id: &str, field: &str, value: &str) -> StoreResult<bool> {
        let now = do_now(&self.sql)?;
        let Some(content_id) = do_content_id(&self.sql, item_id)? else {
            return Ok(false);
        };
        let payload = serde_json::json!({"field": field, "value": value});
        do_tracker_append_raw(
            &self.sql,
            Some(&content_id),
            None,
            "issue.field_set",
            &payload.to_string(),
            None,
            &now,
        )?;
        if let Some(column) = whipplescript_store::items::projection_column(field) {
            self.sql
                .execute(
                    &format!(
                        "UPDATE tracker_issues SET {column} = ?2, updated_at = ?3 WHERE issue_id = ?1"
                    ),
                    &[text(item_id), text(value), text(&now)],
                )
                .map_err(sql_err)?;
        }
        Ok(true)
    }

    /// The DAG conflict view of one issue (`heads` / `state_token` /
    /// `field_conflicts`) — shares the native analysis. `None` if unknown.
    pub fn issue_conflicts(
        &self,
        item_id: &str,
    ) -> StoreResult<Option<whipplescript_store::items::IssueConflicts>> {
        let Some(content_id) = do_content_id(&self.sql, item_id)? else {
            return Ok(None);
        };
        let events = do_load_issue_events(&self.sql, &content_id)?;
        Ok(Some(whipplescript_store::items::analyze_issue_dag(&events)))
    }

    /// Adds a comment (`comment.added`); returns its content-hash id or `None`.
    pub fn add_comment(
        &mut self,
        item_id: &str,
        author: Option<&str>,
        body: &str,
    ) -> StoreResult<Option<String>> {
        let now = do_now(&self.sql)?;
        let Some(content_id) = do_content_id(&self.sql, item_id)? else {
            return Ok(None);
        };
        let payload = serde_json::json!({"author": author, "body": body});
        let comment_id = do_tracker_append_raw(
            &self.sql,
            Some(&content_id),
            None,
            "comment.added",
            &payload.to_string(),
            author,
            &now,
        )?;
        self.sql
            .execute(
                "INSERT OR IGNORE INTO tracker_comments (comment_id, issue_id, author, body, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[text(&comment_id), text(item_id), opt_text(author), text(body), text(&now)],
            )
            .map_err(sql_err)?;
        Ok(Some(comment_id))
    }

    /// Attaches evidence (`evidence.added`); returns its content-hash id.
    pub fn add_evidence(
        &mut self,
        item_id: &str,
        kind: Option<&str>,
        reference: Option<&str>,
        note: Option<&str>,
        added_by: Option<&str>,
    ) -> StoreResult<Option<String>> {
        let now = do_now(&self.sql)?;
        let Some(content_id) = do_content_id(&self.sql, item_id)? else {
            return Ok(None);
        };
        let payload = serde_json::json!({
            "kind": kind, "reference": reference, "note": note, "added_by": added_by,
        });
        let evidence_id = do_tracker_append_raw(
            &self.sql,
            Some(&content_id),
            None,
            "evidence.added",
            &payload.to_string(),
            added_by,
            &now,
        )?;
        self.sql
            .execute(
                "INSERT OR IGNORE INTO tracker_evidence \
                 (evidence_id, issue_id, kind, reference, note, added_by, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    text(&evidence_id),
                    text(item_id),
                    opt_text(kind),
                    opt_text(reference),
                    opt_text(note),
                    opt_text(added_by),
                    text(&now),
                ],
            )
            .map_err(sql_err)?;
        Ok(Some(evidence_id))
    }

    /// Export every event in transport form (the unit another clone unions in).
    pub fn export_events(&self) -> StoreResult<Vec<whipplescript_store::items::TrackerEvent>> {
        let rows = self
            .sql
            .query(
                "SELECT event_id, parents_json, issue_id, kind, payload_json, actor, created_at \
                 FROM tracker_events ORDER BY event_seq",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| whipplescript_store::items::TrackerEvent {
                event_id: as_opt_text(&row[0]).unwrap_or_default(),
                parents: serde_json::from_str(&as_text(&row[1])).unwrap_or_default(),
                issue_id: as_opt_text(&row[2]),
                kind: as_text(&row[3]),
                payload_json: as_text(&row[4]),
                actor: as_opt_text(&row[5]),
                created_at: as_text(&row[6]),
            })
            .collect())
    }

    /// Merge another clone's events (set-union deduped by event_id), re-aliasing
    /// newly seen issues locally and warning on duplicate submissions. The DO
    /// tracker writes projections directly, so imported events are folded here.
    pub fn import_events(
        &mut self,
        events: &[whipplescript_store::items::TrackerEvent],
    ) -> StoreResult<whipplescript_store::items::ImportReport> {
        let mut report = whipplescript_store::items::ImportReport::default();
        for event in events {
            // Re-verify the content-addressed id before admitting an event from
            // an untrusted transport (kept in lockstep with the native store):
            // reject a tampered event whose id != SHA-256 of its own content, or
            // a created event whose id != its issue identity.
            let expected_id = if event.kind == "issue.created" {
                whipplescript_store::items::event_content_id(
                    &event.kind,
                    None,
                    &event.payload_json,
                    event.actor.as_deref(),
                    &[],
                    &event.created_at,
                )
            } else {
                whipplescript_store::items::event_content_id(
                    &event.kind,
                    event.issue_id.as_deref(),
                    &event.payload_json,
                    event.actor.as_deref(),
                    &event.parents,
                    &event.created_at,
                )
            };
            let created_identity_ok = event.kind != "issue.created"
                || event.issue_id.as_deref() == Some(event.event_id.as_str());
            if expected_id != event.event_id || !created_identity_ok {
                report.rejected += 1;
                continue;
            }
            let parents_json =
                serde_json::to_string(&event.parents).map_err(|e| sql_err(e.to_string()))?;
            let changes = self
                .sql
                .execute(
                    "INSERT OR IGNORE INTO tracker_events \
                     (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    &[
                        text(&event.event_id),
                        text(&parents_json),
                        opt_text(event.issue_id.as_deref()),
                        text(&event.kind),
                        text(&event.payload_json),
                        opt_text(event.actor.as_deref()),
                        text(&event.created_at),
                    ],
                )
                .map_err(sql_err)?;
            if changes == 1 {
                report.imported += 1;
            } else {
                // Byte-identical event already held: an idempotent re-transmit
                // (content-addressing makes re-sync free), NOT a duplicate.
                report.skipped += 1;
            }
        }
        // Re-alias every newly-seen issue (a created event with no local alias),
        // in append order, minting this clone's own WS-N.
        let unaliased = self
            .sql
            .query(
                "SELECT issue_id FROM tracker_events \
                 WHERE kind = 'issue.created' AND issue_id IS NOT NULL \
                   AND issue_id NOT IN (SELECT content_id FROM tracker_aliases) \
                 GROUP BY issue_id ORDER BY MIN(event_seq)",
                &[],
            )
            .map_err(sql_err)?;
        let mut new_alias: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for row in &unaliased {
            let content_id = as_text(&row[0]);
            let bumped = self
                .sql
                .query(
                    "UPDATE tracker_counter SET next_id = next_id + 1 WHERE singleton = 1 \
                     RETURNING next_id - 1",
                    &[],
                )
                .map_err(sql_err)?;
            let next = bumped.first().map_or(0, |row| as_i64(&row[0]));
            let alias = format!("WS-{next}");
            self.sql
                .execute(
                    "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
                    &[text(&content_id), text(&alias)],
                )
                .map_err(sql_err)?;
            new_alias.insert(content_id, alias);
            report.new_issues += 1;
        }
        // Genuine duplicate submission: a newly-seen creation describing the same
        // work (queue + title) as a DISTINCT issue already in the log — two
        // independent submissions, distinct content ids. Advisory, never a
        // silent collapse. (A re-transmit shares one id and is deduped above.)
        if !unaliased.is_empty() {
            let created = self
                .sql
                .query(
                    "SELECT issue_id, payload_json FROM tracker_events \
                     WHERE kind = 'issue.created' AND issue_id IS NOT NULL",
                    &[],
                )
                .map_err(sql_err)?;
            let keyed: Vec<(String, String)> = created
                .iter()
                .map(|row| {
                    let cid = as_text(&row[0]);
                    let payload: serde_json::Value =
                        serde_json::from_str(&as_text(&row[1])).unwrap_or(serde_json::Value::Null);
                    let queue = payload
                        .get("queue")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let title = payload
                        .get("title")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    (cid, format!("{queue}\u{1e}{title}"))
                })
                .collect();
            let mut by_key: std::collections::HashMap<&str, Vec<&str>> =
                std::collections::HashMap::new();
            for (cid, key) in &keyed {
                by_key.entry(key).or_default().push(cid);
            }
            for (content_id, alias) in &new_alias {
                if let Some((_, key)) = keyed.iter().find(|(c, _)| c == content_id) {
                    if by_key[key.as_str()].iter().any(|c| *c != content_id) {
                        report.duplicate_submissions.push(alias.clone());
                    }
                }
            }
        }
        self.rebuild_tracker_projection()?;
        Ok(report)
    }

    /// Rebuild the tracker projections (issues/relations/leases/comments/
    /// evidence) by folding the content_id-keyed event log through the alias
    /// bridge — the DO counterpart of the native `rebuild_projection`.
    pub fn rebuild_tracker_projection(&mut self) -> StoreResult<()> {
        // Looped rather than one semicolon-joined batch: see `DoSql::execute`.
        for table in [
            "tracker_issues",
            "tracker_relations",
            "tracker_leases",
            "tracker_comments",
            "tracker_evidence",
        ] {
            self.sql
                .execute(&format!("DELETE FROM {table}"), &[])
                .map_err(sql_err)?;
        }
        let alias_rows = self
            .sql
            .query("SELECT content_id, alias FROM tracker_aliases", &[])
            .map_err(sql_err)?;
        let alias_of: std::collections::HashMap<String, String> = alias_rows
            .iter()
            .map(|row| (as_text(&row[0]), as_text(&row[1])))
            .collect();
        let events = self
            .sql
            .query(
                "SELECT event_id, issue_id, kind, payload_json, created_at, parents_json \
                 FROM tracker_events ORDER BY event_seq",
                &[],
            )
            .map_err(sql_err)?;
        // (event_id, content_id, kind, payload_json, created_at, parents)
        type Row = (String, Option<String>, String, String, String, Vec<String>);
        let rows: Vec<Row> = events
            .iter()
            .map(|row| {
                let parents: Vec<String> =
                    serde_json::from_str(&as_text(&row[5])).unwrap_or_default();
                (
                    as_opt_text(&row[0]).unwrap_or_default(),
                    as_opt_text(&row[1]),
                    as_text(&row[2]),
                    as_text(&row[3]),
                    as_text(&row[4]),
                    parents,
                )
            })
            .collect();
        // Fold in the same deterministic TOPOLOGICAL order as the native store
        // (parents before children; concurrent events by event_id) so a DO log
        // and a native log project identical columns and don't diverge on a
        // non-causal import order.
        for i in whipplescript_store::items::topological_event_order(
            &rows,
            |e| e.0.as_str(),
            |e| e.5.as_slice(),
        ) {
            let (event_id, content_id, kind, payload_str, created_at, _parents) = &rows[i];
            let payload: serde_json::Value =
                serde_json::from_str(payload_str).unwrap_or_else(|_| serde_json::json!({}));
            let issue_alias = content_id.as_deref().and_then(|c| alias_of.get(c).cloned());
            do_fold_tracker_event(
                &self.sql,
                Some(event_id.as_str()),
                issue_alias.as_deref(),
                kind,
                &payload,
                created_at,
                &alias_of,
            )?;
        }
        Ok(())
    }

    /// An issue's comments in chronological order.
    pub fn comments(&self, item_id: &str) -> StoreResult<Vec<whipplescript_store::items::Comment>> {
        let rows = self
            .sql
            .query(
                "SELECT comment_id, author, body, created_at FROM tracker_comments \
                 WHERE issue_id = ?1 ORDER BY created_at, comment_id",
                &[text(item_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| whipplescript_store::items::Comment {
                id: as_text(&row[0]),
                author: as_opt_text(&row[1]),
                body: as_text(&row[2]),
                created_at: as_text(&row[3]),
            })
            .collect())
    }

    /// An issue's attached evidence in chronological order.
    pub fn evidence(
        &self,
        item_id: &str,
    ) -> StoreResult<Vec<whipplescript_store::items::Evidence>> {
        let rows = self
            .sql
            .query(
                "SELECT evidence_id, kind, reference, note, added_by, created_at \
                 FROM tracker_evidence WHERE issue_id = ?1 ORDER BY created_at, evidence_id",
                &[text(item_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| whipplescript_store::items::Evidence {
                id: as_text(&row[0]),
                kind: as_opt_text(&row[1]),
                reference: as_opt_text(&row[2]),
                note: as_opt_text(&row[3]),
                added_by: as_opt_text(&row[4]),
                created_at: as_text(&row[5]),
            })
            .collect())
    }
}

/// Fold one tracker event into the DO projections during a rebuild (the DO
/// counterpart of the native `fold_event`). `issue_id` is the alias (resolved
/// from the event's content_id); relation payloads carry content_ids that map
/// back to aliases via `alias_of`.
fn do_fold_tracker_event(
    sql: &impl DoSql,
    event_id: Option<&str>,
    issue_id: Option<&str>,
    kind: &str,
    payload: &serde_json::Value,
    created_at: &str,
    alias_of: &std::collections::HashMap<String, String>,
) -> StoreResult<()> {
    let str_of = |key: &str| {
        payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let alias_for = |cid: Option<String>| cid.and_then(|c| alias_of.get(&c).cloned());
    match kind {
        "issue.created" => {
            if let Some(issue) = issue_id {
                let labels_json = payload
                    .get("labels")
                    .map_or_else(|| "[]".to_owned(), std::string::ToString::to_string);
                let metadata_json = payload
                    .get("metadata")
                    .map_or_else(|| "{}".to_owned(), std::string::ToString::to_string);
                sql.execute(
                    "INSERT INTO tracker_issues \
                     (issue_id, queue, title, body, status, labels_json, metadata_json, filed_by, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?8)",
                    &[
                        text(issue),
                        text(&str_of("queue").unwrap_or_default()),
                        text(&str_of("title").unwrap_or_default()),
                        text(&str_of("body").unwrap_or_default()),
                        text(&labels_json),
                        text(&metadata_json),
                        opt_text(str_of("filed_by").as_deref()),
                        text(created_at),
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        "issue.field_set" => {
            if let (Some(issue), Some(field), Some(value)) =
                (issue_id, str_of("field"), str_of("value"))
            {
                if let Some(column) = whipplescript_store::items::projection_column(&field) {
                    sql.execute(
                        &format!(
                            "UPDATE tracker_issues SET {column} = ?2, updated_at = ?3 WHERE issue_id = ?1"
                        ),
                        &[text(issue), text(&value), text(created_at)],
                    )
                    .map_err(sql_err)?;
                }
            }
        }
        "issue.closed" | "issue.canceled" | "issue.reopened" => {
            if let Some(issue) = issue_id {
                let status = match kind {
                    "issue.closed" => "closed",
                    "issue.canceled" => "canceled",
                    _ => "open",
                };
                sql.execute(
                    "UPDATE tracker_issues SET status = ?2, \
                     claim_summary = COALESCE(?3, claim_summary), updated_at = ?4 WHERE issue_id = ?1",
                    &[text(issue), text(status), opt_text(str_of("summary").as_deref()), text(created_at)],
                )
                .map_err(sql_err)?;
            }
        }
        "relation.added" => {
            if let (Some(from), Some(to)) = (alias_for(str_of("from")), alias_for(str_of("to"))) {
                sql.execute(
                    "INSERT OR IGNORE INTO tracker_relations (from_issue, to_issue, kind, dep_kind) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(&from),
                        text(&to),
                        text(&str_of("kind").unwrap_or_else(|| "blocks".to_owned())),
                        opt_text(str_of("dep_kind").as_deref()),
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        "relation.removed" => {
            if let (Some(from), Some(to)) = (alias_for(str_of("from")), alias_for(str_of("to"))) {
                sql.execute(
                    "DELETE FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = ?3",
                    &[text(&from), text(&to), text(&str_of("kind").unwrap_or_else(|| "blocks".to_owned()))],
                )
                .map_err(sql_err)?;
            }
        }
        "comment.added" => {
            if let (Some(comment_id), Some(issue)) = (event_id, issue_id) {
                sql.execute(
                    "INSERT OR IGNORE INTO tracker_comments (comment_id, issue_id, author, body, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        text(comment_id),
                        text(issue),
                        opt_text(str_of("author").as_deref()),
                        text(&str_of("body").unwrap_or_default()),
                        text(created_at),
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        "evidence.added" => {
            if let (Some(evidence_id), Some(issue)) = (event_id, issue_id) {
                sql.execute(
                    "INSERT OR IGNORE INTO tracker_evidence \
                     (evidence_id, issue_id, kind, reference, note, added_by, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    &[
                        text(evidence_id),
                        text(issue),
                        opt_text(str_of("kind").as_deref()),
                        opt_text(str_of("reference").as_deref()),
                        opt_text(str_of("note").as_deref()),
                        opt_text(str_of("added_by").as_deref()),
                        text(created_at),
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        "claim.acquired" => {
            // Keyed by the acquire event's own event_id (content hash), like
            // comments/evidence — clone-local payload ids collide on merge.
            if let (Some(lease_id), Some(issue)) = (event_id, issue_id) {
                sql.execute(
                    "INSERT OR IGNORE INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                    &[
                        text(lease_id),
                        text(issue),
                        opt_text(str_of("actor").as_deref()),
                        text(created_at),
                        opt_text(payload.get("expires_at").and_then(serde_json::Value::as_str)),
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        "claim.renewed" => {
            sql.execute(
                "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
                &[
                    opt_text(str_of("lease_id").as_deref()),
                    opt_text(
                        payload
                            .get("expires_at")
                            .and_then(serde_json::Value::as_str),
                    ),
                ],
            )
            .map_err(sql_err)?;
        }
        "claim.released" | "claim.expired" => {
            sql.execute(
                "UPDATE tracker_leases SET released_at = ?2 WHERE lease_id = ?1",
                &[
                    opt_text(str_of("lease_id").as_deref()),
                    text(&str_of("released_at").unwrap_or_else(|| created_at.to_owned())),
                ],
            )
            .map_err(sql_err)?;
        }
        _ => {}
    }
    Ok(())
}

// -- Coordination over DoSql (DR-0033 chunk 5a) -----------------------------
//
// Leases (slot-bounded, TTL), ledgers (append-commute, bounded retention), and
// coord_counters (atomic consume with lazy period reset) ported to the DO's one SQLite.
// Natively these live in a separate coordination store; on the DO they are the
// `coord_leases` / `coord_ledger_seq` / `coord_ledger_entries` / `coord_counters` tables. The native
// atomic pairs used a rusqlite transaction; the DO single-writer per-invocation
// model supplies that atomicity. Only the 9 required `*_for_owner` (+
// `release_all_for_holder`) methods are ported; the 7
// shared-owner convenience forms are the trait's inherited defaults.

/// Empty owner normalizes to the shared partition (mirrors `normalized_owner`).
fn do_norm_owner(owner: &str) -> &str {
    if owner.trim().is_empty() {
        "shared"
    } else {
        owner
    }
}

impl<Sql: DoSql> Coordination for DoSqliteStore<Sql> {
    fn ledger_positions(&self) -> StoreResult<Vec<(String, String, i64)>> {
        let rows = self
            .sql
            .query(
                "SELECT owner, ledger, next_seq FROM coord_ledger_seq ORDER BY owner, ledger",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| (as_text(&row[0]), as_text(&row[1]), as_i64(&row[2])))
            .collect())
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
        let owner = do_norm_owner(owner);
        self.sql
            .execute(
                "DELETE FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND expires_at <= datetime('now')",
                &[text(owner), text(resource), text(key)],
            )
            .map_err(sql_err)?;
        let already = self
            .sql
            .query(
                "SELECT COUNT(*) FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4",
                &[text(owner), text(resource), text(key), text(holder)],
            )
            .map_err(sql_err)?;
        if already.first().map(|row| as_i64(&row[0])).unwrap_or(0) > 0 {
            return Ok(AcquireOutcome::Held);
        }
        let holders = self
            .sql
            .query(
                "SELECT COUNT(*) FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3",
                &[text(owner), text(resource), text(key)],
            )
            .map_err(sql_err)?;
        if holders.first().map(|row| as_i64(&row[0])).unwrap_or(0) < slots {
            self.sql
                .execute(
                    "INSERT INTO coord_leases (owner, resource, key, holder, expires_at) VALUES (?1, ?2, ?3, ?4, datetime('now', ?5))",
                    &[text(owner), text(resource), text(key), text(holder), text(&format!("+{ttl_seconds} seconds"))],
                )
                .map_err(sql_err)?;
            return Ok(AcquireOutcome::Held);
        }
        let current = self
            .sql
            .query(
                "SELECT holder FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 ORDER BY acquired_at",
                &[text(owner), text(resource), text(key)],
            )
            .map_err(sql_err)?;
        Ok(AcquireOutcome::Contended {
            holders: current.iter().map(|row| as_text(&row[0])).collect(),
        })
    }

    fn release_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        holder: &str,
    ) -> StoreResult<bool> {
        let owner = do_norm_owner(owner);
        let changed = self
            .sql
            .execute(
                "DELETE FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4",
                &[text(owner), text(resource), text(key), text(holder)],
            )
            .map_err(sql_err)?;
        Ok(changed >= 1)
    }

    fn renew_lease_for_owner(
        &mut self,
        owner: &str,
        resource: &str,
        key: &str,
        ttl_seconds: i64,
        holder: &str,
    ) -> StoreResult<Option<String>> {
        let owner = do_norm_owner(owner);
        // One atomic UPDATE of a still-live hold; the DO's single-writer model
        // supplies the atomicity a native rusqlite transaction would.
        let changed = self
            .sql
            .execute(
                "UPDATE coord_leases SET expires_at = datetime('now', ?5) \
                 WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4 \
                 AND expires_at > datetime('now')",
                &[
                    text(owner),
                    text(resource),
                    text(key),
                    text(holder),
                    text(&format!("+{ttl_seconds} seconds")),
                ],
            )
            .map_err(sql_err)?;
        if changed == 0 {
            return Ok(None);
        }
        let rows = self
            .sql
            .query(
                "SELECT expires_at FROM coord_leases WHERE owner = ?1 AND resource = ?2 AND key = ?3 AND holder = ?4",
                &[text(owner), text(resource), text(key), text(holder)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn release_all_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        let changed = self
            .sql
            .execute(
                "DELETE FROM coord_leases WHERE holder = ?1",
                &[text(holder)],
            )
            .map_err(sql_err)?;
        Ok(changed as usize)
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
        let owner = do_norm_owner(owner);
        self.sql
            .execute(
                "INSERT OR IGNORE INTO coord_ledger_seq (owner, ledger, next_seq) VALUES (?1, ?2, 1)",
                &[text(owner), text(ledger)],
            )
            .map_err(sql_err)?;
        let bumped = self
            .sql
            .query(
                "UPDATE coord_ledger_seq SET next_seq = next_seq + 1 WHERE owner = ?1 AND ledger = ?2 RETURNING next_seq - 1",
                &[text(owner), text(ledger)],
            )
            .map_err(sql_err)?;
        let seq = bumped
            .first()
            .map(|row| as_i64(&row[0]))
            .ok_or_else(|| StoreError::Conflict("coord_ledger_seq row missing".to_owned()))?;
        self.sql
            .execute(
                "INSERT INTO coord_ledger_entries (owner, ledger, partition, seq, payload_json, appended_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[text(owner), text(ledger), text(partition), int(seq), text(payload_json), text(appended_by)],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "DELETE FROM coord_ledger_entries WHERE owner = ?1 AND ledger = ?2 AND appended_at <= datetime('now', ?3)",
                &[text(owner), text(ledger), text(&format!("-{retain_seconds} seconds"))],
            )
            .map_err(sql_err)?;
        Ok(seq)
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
        let owner = do_norm_owner(owner);
        self.sql
            .execute(
                "INSERT OR IGNORE INTO coord_counters (owner, counter, key, consumed, period) VALUES (?1, ?2, ?3, 0, ?4)",
                &[text(owner), text(counter), text(key), text(period)],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "UPDATE coord_counters SET consumed = 0, period = ?4 WHERE owner = ?1 AND counter = ?2 AND key = ?3 AND period != ?4",
                &[text(owner), text(counter), text(key), text(period)],
            )
            .map_err(sql_err)?;
        let current = self
            .sql
            .query(
                "SELECT consumed FROM coord_counters WHERE owner = ?1 AND counter = ?2 AND key = ?3",
                &[text(owner), text(counter), text(key)],
            )
            .map_err(sql_err)?;
        let consumed = current.first().map(|row| as_i64(&row[0])).unwrap_or(0);
        // Guard the workflow-authored `amount` against i64 overflow (mirrors the
        // native store): a near-MAX amount would wrap the check and drive the
        // counter negative (silent cap bypass). checked_add fails closed to
        // `Over`, never charging.
        if let Some(total) = consumed.checked_add(amount) {
            if amount >= 0 && total <= cap {
                self.sql
                    .execute(
                        "UPDATE coord_counters SET consumed = consumed + ?4 WHERE owner = ?1 AND counter = ?2 AND key = ?3",
                        &[text(owner), text(counter), text(key), int(amount)],
                    )
                    .map_err(sql_err)?;
                return Ok(ConsumeOutcome::Ok {
                    remaining: cap - total,
                });
            }
        }
        Ok(ConsumeOutcome::Over {
            remaining: (cap - consumed).max(0),
        })
    }

    fn list_leases_for_owner(
        &self,
        owner: Option<&str>,
        resource: Option<&str>,
    ) -> StoreResult<Vec<LeaseRow>> {
        let owner = owner.map(do_norm_owner);
        let rows = self
            .sql
            .query(
                "SELECT owner, resource, key, holder, acquired_at, expires_at FROM coord_leases WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR resource = ?2) ORDER BY owner, resource, key, acquired_at",
                &[opt_text(owner), opt_text(resource)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| LeaseRow {
                owner: as_text(&row[0]),
                resource: as_text(&row[1]),
                key: as_text(&row[2]),
                holder: as_text(&row[3]),
                acquired_at: as_text(&row[4]),
                expires_at: as_text(&row[5]),
            })
            .collect())
    }

    fn list_entries_for_owner(
        &self,
        owner: Option<&str>,
        ledger: Option<&str>,
        partition: Option<&str>,
    ) -> StoreResult<Vec<LedgerEntry>> {
        let owner = owner.map(do_norm_owner);
        let rows = self
            .sql
            .query(
                "SELECT owner, ledger, partition, seq, payload_json, appended_by, appended_at FROM coord_ledger_entries WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR ledger = ?2) AND (?3 IS NULL OR partition = ?3) ORDER BY owner, ledger, seq",
                &[opt_text(owner), opt_text(ledger), opt_text(partition)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| LedgerEntry {
                owner: as_text(&row[0]),
                ledger: as_text(&row[1]),
                partition: as_text(&row[2]),
                seq: as_i64(&row[3]),
                payload_json: as_text(&row[4]),
                appended_by: as_text(&row[5]),
                appended_at: as_text(&row[6]),
            })
            .collect())
    }

    fn list_counters_for_owner(
        &self,
        owner: Option<&str>,
        counter: Option<&str>,
    ) -> StoreResult<Vec<CounterRow>> {
        let owner = owner.map(do_norm_owner);
        let rows = self
            .sql
            .query(
                "SELECT owner, counter, key, consumed, period FROM coord_counters WHERE (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR counter = ?2) ORDER BY owner, counter, key",
                &[opt_text(owner), opt_text(counter)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| CounterRow {
                owner: as_text(&row[0]),
                counter: as_text(&row[1]),
                key: as_text(&row[2]),
                consumed: as_i64(&row[3]),
                period: as_text(&row[4]),
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use rusqlite::types::{Value, ValueRef};
    use rusqlite::Connection;

    // `Rc<Connection>` so the handle is `Clone` (the production `DoSql` handles
    // are shared via `Rc`; a clone is the SAME in-memory DB, as the DO's single
    // SQLite requires). This lets `DoInstanceDriver` require `Sql: Clone` for
    // binding-driven provider selection (e.g. the memory provider).
    #[derive(Clone)]
    pub(crate) struct RusqliteDoSql {
        conn: std::rc::Rc<Connection>,
    }

    fn to_value(v: &SqlValue) -> Value {
        match v {
            SqlValue::Null => Value::Null,
            SqlValue::Int(n) => Value::Integer(*n),
            SqlValue::Text(s) => Value::Text(s.clone()),
        }
    }

    fn from_ref(r: ValueRef<'_>) -> SqlValue {
        match r {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(n) => SqlValue::Int(n),
            ValueRef::Real(f) => SqlValue::Int(f as i64),
            ValueRef::Text(t) => SqlValue::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(_) => SqlValue::Null,
        }
    }

    impl DoSql for RusqliteDoSql {
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.conn
                .execute(sql, rusqlite::params_from_iter(params.iter().map(to_value)))
                .map(|n| n as u64)
                .map_err(|e| e.to_string())
        }

        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            let mut stmt = self.conn.prepare(sql).map_err(|e| e.to_string())?;
            let cols = stmt.column_count();
            let rows = stmt
                .query_map(
                    rusqlite::params_from_iter(params.iter().map(to_value)),
                    |row| {
                        let mut out = Vec::with_capacity(cols);
                        for i in 0..cols {
                            out.push(from_ref(row.get_ref(i)?));
                        }
                        Ok(out)
                    },
                )
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            Ok(rows)
        }
    }

    pub(crate) fn store() -> DoSqliteStore<RusqliteDoSql> {
        let conn = Connection::open_in_memory().expect("sqlite");
        conn.execute_batch(
            r#"
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT);
            INSERT INTO schema_migrations (version, name) VALUES (1, 'init');
            INSERT INTO schema_migrations (version, name) VALUES (2, 'provider-trust-evidence');
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL, payload_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
                source TEXT NOT NULL, causation_id TEXT, correlation_id TEXT, idempotency_key TEXT,
                format_version INTEGER
            );
            CREATE UNIQUE INDEX events_instance_idempotency_key_idx
                ON events(instance_id, idempotency_key)
                WHERE idempotency_key IS NOT NULL;
            CREATE TABLE facts (
                fact_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, program_version_id TEXT,
                revision_epoch INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL,
                key TEXT NOT NULL DEFAULT '', value_json TEXT NOT NULL DEFAULT '{}',
                source_event_id TEXT, source_rule TEXT, schema_id TEXT,
                provenance_class TEXT NOT NULL DEFAULT 'derived', correlation_id TEXT,
                source_span_json TEXT, consumed_at TEXT, updated_at TEXT,
                UNIQUE(instance_id, name, key)
            );
            CREATE TABLE instances (
                instance_id TEXT PRIMARY KEY, program_id TEXT NOT NULL, version_id TEXT NOT NULL,
                revision_epoch INTEGER NOT NULL DEFAULT 0, workflow_principal TEXT NOT NULL,
                effective_authority TEXT NOT NULL, status TEXT NOT NULL, input_json TEXT NOT NULL,
                started_at TEXT, last_event_id TEXT, last_error TEXT, completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE programs (
                program_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE program_versions (
                version_id TEXT PRIMARY KEY, program_id TEXT NOT NULL DEFAULT '',
                source_hash TEXT NOT NULL DEFAULT '', ir_hash TEXT NOT NULL DEFAULT '',
                compiler_version TEXT NOT NULL DEFAULT '',
                declared_capabilities TEXT NOT NULL DEFAULT '[]',
                declared_profiles TEXT NOT NULL DEFAULT '[]',
                declared_skills TEXT NOT NULL DEFAULT '[]',
                declared_schemas TEXT NOT NULL DEFAULT '[]',
                analysis_summary TEXT NOT NULL DEFAULT '{}',
                generated_artifacts TEXT NOT NULL DEFAULT '[]', artifact_root TEXT,
                UNIQUE(program_id, source_hash, ir_hash)
            );
            CREATE TABLE artifacts (
                artifact_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, kind TEXT NOT NULL,
                path TEXT NOT NULL, content_hash TEXT, mime_type TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE workspaces (
                workspace_id TEXT PRIMARY KEY, instance_id TEXT, effect_id TEXT, run_id TEXT,
                provider TEXT, policy TEXT NOT NULL, uri TEXT NOT NULL, status TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(instance_id, effect_id, run_id, policy)
            );
            CREATE TABLE diagnostics (
                diagnostic_id TEXT PRIMARY KEY, instance_id TEXT, program_id TEXT,
                program_version_id TEXT, severity TEXT NOT NULL, code TEXT, message TEXT NOT NULL,
                source_span_json TEXT, subject_type TEXT, subject_id TEXT, event_id TEXT,
                effect_id TEXT, run_id TEXT, assertion_id TEXT,
                evidence_ids_json TEXT NOT NULL DEFAULT '[]',
                artifact_ids_json TEXT NOT NULL DEFAULT '[]', causation_id TEXT, correlation_id TEXT,
                idempotency_key TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, kind TEXT NOT NULL,
                subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, causation_id TEXT,
                correlation_id TEXT, summary TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE evidence_links (
                link_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, instance_id TEXT NOT NULL,
                target_type TEXT NOT NULL, target_id TEXT NOT NULL, relation TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(evidence_id, target_type, target_id, relation)
            );
            CREATE TABLE effects (
                effect_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, kind TEXT NOT NULL,
                target TEXT, input_json TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL,
                created_by_rule TEXT NOT NULL DEFAULT '', program_version_id TEXT,
                revision_epoch INTEGER NOT NULL DEFAULT 0, profile TEXT,
                required_capabilities TEXT NOT NULL DEFAULT '[]', policy_block_reason TEXT,
                policy_block_category TEXT, created_by_event_id TEXT, correlation_id TEXT,
                idempotency_key TEXT, timeout_seconds INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE effect_dependencies (
                instance_id TEXT NOT NULL, downstream_effect_id TEXT NOT NULL,
                upstream_effect_id TEXT NOT NULL, predicate TEXT NOT NULL
            );
            CREATE TABLE leases (
                lease_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, run_id TEXT NOT NULL,
                effect_id TEXT NOT NULL, worker_id TEXT, status TEXT NOT NULL,
                expires_at TEXT NOT NULL, released_at TEXT
            );
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                provider TEXT NOT NULL, worker_id TEXT NOT NULL, status TEXT NOT NULL,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT,
                exit_code INTEGER, summary TEXT, metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE effect_cancellation_requests (
                request_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, effect_id TEXT NOT NULL,
                revision_id TEXT, reason TEXT, requested_by TEXT NOT NULL DEFAULT 'kernel',
                causation_event_id TEXT, status TEXT NOT NULL, idempotency_key TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_by_event_id TEXT
            );
            CREATE TABLE instance_revisions (
                revision_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                from_version_id TEXT NOT NULL, to_version_id TEXT NOT NULL,
                activated_by_event_id TEXT NOT NULL, activation_policy_json TEXT NOT NULL DEFAULT '{}',
                cancellation_policy TEXT NOT NULL, status TEXT NOT NULL, idempotency_key TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE workflow_invocations (
                invocation_id TEXT PRIMARY KEY, parent_instance_id TEXT NOT NULL,
                parent_effect_id TEXT NOT NULL, parent_program_version_id TEXT,
                parent_revision_epoch INTEGER NOT NULL, child_instance_id TEXT NOT NULL,
                child_program_version_id TEXT, child_revision_epoch INTEGER,
                target_workflow TEXT NOT NULL, input_json TEXT NOT NULL DEFAULT '{}',
                source_span_json TEXT, idempotency_key TEXT UNIQUE, status TEXT NOT NULL DEFAULT 'running',
                terminal_event_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT
            );
            CREATE TABLE project_context_docs (
                position INTEGER PRIMARY KEY, path TEXT NOT NULL,
                content_hash TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE compute_result_cache (
                content_key TEXT PRIMARY KEY, effect_kind TEXT NOT NULL,
                result_json TEXT NOT NULL, source_instance_id TEXT NOT NULL,
                source_effect_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE content_blobs (
                id TEXT PRIMARY KEY, body TEXT NOT NULL, byte_len INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE files (
                key TEXT PRIMARY KEY, content TEXT NOT NULL
            );
            CREATE TABLE script_capabilities (
                name TEXT PRIMARY KEY, argv_json TEXT NOT NULL, sha256 TEXT NOT NULL,
                env_json TEXT NOT NULL DEFAULT '{}', hermetic INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE skills (
                skill_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, version TEXT NOT NULL,
                source TEXT NOT NULL, source_path TEXT NOT NULL, content_hash TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '', required_capabilities TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE skill_attachments (
                attachment_id TEXT PRIMARY KEY, scope_type TEXT NOT NULL, scope_id TEXT NOT NULL,
                skill_id TEXT NOT NULL, UNIQUE(scope_type, scope_id, skill_id)
            );
            CREATE TABLE package_registrations (
                package_id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            );
            CREATE TABLE capability_schemas (
                capability TEXT PRIMARY KEY, description TEXT NOT NULL, schema_json TEXT NOT NULL,
                registered_by_package_id TEXT
            );
            CREATE TABLE effect_providers (
                provider_id TEXT NOT NULL, effect_kind TEXT NOT NULL, provider TEXT NOT NULL,
                capability TEXT NOT NULL, config_json TEXT NOT NULL, registered_by_package_id TEXT,
                UNIQUE(effect_kind, provider)
            );
            CREATE TABLE provider_trust_evidence (
                effect_kind TEXT NOT NULL, provider TEXT NOT NULL,
                pinned_digest TEXT,
                claim_class TEXT, claim_signer TEXT, claim_filed_at TEXT, claim_expires_at TEXT,
                operator_run INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (effect_kind, provider),
                CHECK (claim_class IS NULL OR (claim_signer IS NOT NULL AND claim_expires_at IS NOT NULL))
            );
            CREATE TABLE profiles (
                profile_id TEXT NOT NULL, name TEXT PRIMARY KEY, description TEXT NOT NULL,
                enforcement_mode TEXT NOT NULL, allowed_capabilities TEXT NOT NULL,
                config_json TEXT NOT NULL
            );
            CREATE TABLE capability_bindings (
                binding_id TEXT PRIMARY KEY, program_id TEXT, capability TEXT NOT NULL,
                provider TEXT NOT NULL, config_json TEXT NOT NULL
            );
            CREATE TABLE agent_turn_snapshots (
                effect_id TEXT PRIMARY KEY, snapshot_json TEXT NOT NULL
            );
            CREATE TABLE public_turn_commands (
                command_id TEXT PRIMARY KEY, turn_command_id TEXT NOT NULL,
                kind TEXT NOT NULL, text TEXT NOT NULL, images_json TEXT NOT NULL DEFAULT '[]',
                position INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                announced INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, applied_at TEXT
            );
            CREATE TABLE tracker_events (
                event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT, parents_json TEXT NOT NULL DEFAULT '[]',
                issue_id TEXT, kind TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}', actor TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_issues (
                issue_id TEXT PRIMARY KEY, queue TEXT NOT NULL, title TEXT NOT NULL,
                body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open',
                labels_json TEXT NOT NULL DEFAULT '[]', metadata_json TEXT NOT NULL DEFAULT '{}',
                claim_summary TEXT, assigned_to TEXT, filed_by TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_relations (
                from_issue TEXT NOT NULL, to_issue TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'blocks', dep_kind TEXT,
                PRIMARY KEY (from_issue, to_issue, kind)
            );
            CREATE TABLE tracker_leases (
                lease_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, actor TEXT NOT NULL,
                acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT, released_at TEXT
            );
            CREATE TABLE tracker_counter (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1), next_id INTEGER NOT NULL
            );
            INSERT INTO tracker_counter (singleton, next_id) VALUES (1, 1);
            CREATE TABLE tracker_aliases (
                content_id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE
            );
            CREATE TABLE tracker_comments (
                comment_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, author TEXT,
                body TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE tracker_evidence (
                evidence_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, kind TEXT, reference TEXT,
                note TEXT, added_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_tracker_issues_queue ON tracker_issues(queue, status);
            CREATE INDEX idx_tracker_leases_issue ON tracker_leases(issue_id, released_at);
            CREATE INDEX idx_tracker_events_issue ON tracker_events(issue_id, kind);
            CREATE UNIQUE INDEX idx_tracker_events_id ON tracker_events(event_id);
            CREATE TABLE coord_leases (
                owner TEXT NOT NULL, resource TEXT NOT NULL, key TEXT NOT NULL, holder TEXT NOT NULL,
                acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TEXT NOT NULL,
                PRIMARY KEY (owner, resource, key, holder)
            );
            CREATE TABLE coord_ledger_seq (
                owner TEXT NOT NULL, ledger TEXT NOT NULL, next_seq INTEGER NOT NULL,
                PRIMARY KEY (owner, ledger)
            );
            CREATE TABLE coord_ledger_entries (
                owner TEXT NOT NULL, ledger TEXT NOT NULL, partition TEXT NOT NULL, seq INTEGER NOT NULL,
                payload_json TEXT NOT NULL, appended_by TEXT NOT NULL,
                appended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (owner, ledger, seq)
            );
            CREATE TABLE coord_counters (
                owner TEXT NOT NULL, counter TEXT NOT NULL, key TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0, period TEXT NOT NULL, PRIMARY KEY (owner, counter, key)
            );
            "#,
        )
        .expect("schema");
        DoSqliteStore::new(RusqliteDoSql {
            conn: std::rc::Rc::new(conn),
        })
    }
}

/// Persist an agent turn's `BrokeredTurnSnapshot` (as JSON) keyed by effect, so a
/// multi-round turn survives DO eviction between provider rounds (DR-0033 chunk 5b).
pub fn do_save_agent_snapshot<Sql: DoSql>(
    sql: &Sql,
    effect_id: &str,
    snapshot_json: &str,
) -> StoreResult<()> {
    sql.execute(
        "INSERT INTO agent_turn_snapshots (effect_id, snapshot_json) VALUES (?1, ?2) \
         ON CONFLICT(effect_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
        &[text(effect_id), text(snapshot_json)],
    )
    .map_err(sql_err)?;
    Ok(())
}

/// Load a persisted agent-turn snapshot JSON, or `None` on the first round.
pub fn do_load_agent_snapshot<Sql: DoSql>(
    sql: &Sql,
    effect_id: &str,
) -> StoreResult<Option<String>> {
    let rows = sql
        .query(
            "SELECT snapshot_json FROM agent_turn_snapshots WHERE effect_id = ?1",
            &[text(effect_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| as_text(&row[0])))
}

/// Read unconsumed interactive commands for one live agent effect. The rows
/// remain pending until the caller has durably saved a machine snapshot that
/// includes their ids.
pub fn do_pending_turn_commands<Sql: DoSql>(
    sql: &Sql,
    effect_id: &str,
    kind: whipplescript_kernel::harness_loop::TurnCommandKind,
) -> StoreResult<Vec<whipplescript_kernel::harness_loop::PendingTurnCommand>> {
    let kind = match kind {
        whipplescript_kernel::harness_loop::TurnCommandKind::Steer => "steer",
        whipplescript_kernel::harness_loop::TurnCommandKind::FollowUp => "follow_up",
    };
    let rows = sql
        .query(
            "SELECT command_id, text, images_json FROM public_turn_commands \
             WHERE turn_command_id = ?1 AND kind = ?2 AND status = 'pending' \
             ORDER BY position, created_at, command_id",
            &[text(effect_id), text(kind)],
        )
        .map_err(sql_err)?;
    rows.into_iter()
        .map(|row| {
            let images = serde_json::from_str(&as_text(&row[2]))
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            Ok(whipplescript_kernel::harness_loop::PendingTurnCommand {
                command_id: as_text(&row[0]),
                text: as_text(&row[1]),
                images,
            })
        })
        .collect()
}

/// Acknowledge commands only after the snapshot containing their ids is
/// durable. Repeating this after a crash is harmless.
pub fn do_mark_turn_commands_applied<Sql: DoSql>(
    sql: &Sql,
    effect_id: &str,
    command_ids: &std::collections::BTreeSet<String>,
) -> StoreResult<()> {
    for command_id in command_ids {
        sql.execute(
            "UPDATE public_turn_commands SET status = 'applied', \
             applied_at = CURRENT_TIMESTAMP WHERE turn_command_id = ?1 \
             AND command_id = ?2 AND status = 'pending'",
            &[text(effect_id), text(command_id)],
        )
        .map_err(sql_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backs `DoSql` with real in-memory SQLite, so the ported store SQL is
    /// checked against an actual engine.
    use super::test_support::store;

    /// P1: the production `DoSqlStorage` drives the file plane over REAL DO
    /// SQLite (the `files` table) through the `FileStore` seam — write, read,
    /// append, overwrite-replaces, exists, and missing-errors.
    #[test]
    fn do_sql_storage_round_trips_the_file_plane_over_real_sqlite() {
        use whipplescript_store::files::FileStore;
        // `store()` applies the schema (now carrying the `files` table); take its
        // real `RusqliteDoSql` and back the file plane with it.
        let files = crate::DoFileStore::new(DoSqlStorage::new(store().sql));
        let path = std::path::Path::new("notes/todo.txt");

        assert!(!files.exists(path));
        assert!(files.read_to_string(path).is_err(), "missing file errors");
        files.write(path, b"hello").expect("write");
        assert!(files.exists(path));
        assert_eq!(files.read_to_string(path).expect("read"), "hello");
        files.append(path, b" world").expect("append");
        assert_eq!(files.read_to_string(path).expect("read"), "hello world");
        // A write REPLACES (does not append) — the live path->bytes semantics.
        files.write(path, b"fresh").expect("rewrite");
        assert_eq!(files.read_to_string(path).expect("read"), "fresh");
        // P2: remove drops the file; removing an absent path is a no-op.
        files.remove(path).expect("remove");
        assert!(!files.exists(path), "removed file is gone");
        files.remove(path).expect("remove absent is idempotent");
    }

    #[test]
    fn do_work_items_file_claim_release_finish_over_dosql() {
        let mut store = store();
        // File two items; ids are minted sequentially (WS-1, WS-2).
        let a = WorkItems::file_item(
            &mut store,
            "triage",
            "first",
            "b1",
            &[],
            &serde_json::json!({}),
            Some("f"),
        )
        .expect("file a");
        let b = WorkItems::file_item(
            &mut store,
            "triage",
            "second",
            "",
            &[],
            &serde_json::json!({}),
            None,
        )
        .expect("file b");
        assert_eq!(a.id, "WS-1");
        assert_eq!(b.id, "WS-2");

        // Both are ready (open + unclaimed); listing filters by queue/status.
        assert_eq!(
            WorkItems::ready_items(&store, "triage")
                .expect("ready")
                .len(),
            2
        );
        assert_eq!(
            WorkItems::list_items(&store, Some("triage"), Some("open"))
                .expect("list")
                .len(),
            2
        );

        // Claim WS-1: the first claim wins; a second contends with the holder.
        assert_eq!(
            WorkItems::claim_item(&mut store, "WS-1", "worker:x", None).expect("claim"),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            WorkItems::claim_item(&mut store, "WS-1", "worker:y", None).expect("reclaim"),
            ClaimOutcome::AlreadyClaimed {
                holder: "worker:x".to_owned()
            }
        );
        assert_eq!(
            WorkItems::claim_item(&mut store, "WS-9", "worker:x", None).expect("missing"),
            ClaimOutcome::NotFound
        );
        // Only WS-2 remains ready now.
        assert_eq!(
            WorkItems::ready_items(&store, "triage")
                .expect("ready2")
                .len(),
            1
        );

        // Holder-release returns WS-1 to open; then finish it.
        assert_eq!(
            WorkItems::release_claims_for_holder(&mut store, "worker:x").expect("release"),
            1
        );
        assert_eq!(
            WorkItems::get_item(&store, "WS-1")
                .expect("get")
                .expect("row")
                .status,
            "open"
        );
        assert!(WorkItems::finish_item(&mut store, "WS-1", Some("done by hand")).expect("finish"));
        assert_eq!(
            WorkItems::get_item(&store, "WS-1")
                .expect("get2")
                .expect("row")
                .status,
            "closed"
        );
    }

    /// DO parity (ADR-0002 phase B): the edge-host tracker is content-addressed
    /// (events keyed by opaque content_id, not WS-N), shares the native conflict
    /// analysis, and merges via export/import — two DO clones editing one issue
    /// converge to a surfaced conflict, exactly like native.
    #[test]
    fn do_tracker_is_content_addressed_and_merges_to_a_conflict() {
        let mut a = store();
        let issue =
            WorkItems::file_item(&mut a, "q", "Shared", "", &[], &serde_json::json!({}), None)
                .expect("file");
        assert_eq!(issue.id, "WS-1");

        // Identity = content hash; no event is keyed by the WS-N alias.
        let cid = do_content_id(&a.sql, "WS-1")
            .unwrap()
            .expect("alias resolves");
        assert_eq!(cid.len(), 64, "content_id is a SHA-256");
        let by_alias = a
            .sql
            .query(
                "SELECT COUNT(*) FROM tracker_events WHERE issue_id = 'WS-1'",
                &[],
            )
            .unwrap();
        assert_eq!(as_i64(&by_alias[0][0]), 0, "no event keyed by the alias");

        // A second DO clone imports A's issue and re-aliases it locally.
        let mut b = store();
        let report = b.import_events(&a.export_events().unwrap()).unwrap();
        assert_eq!(report.new_issues, 1);
        assert_eq!(b.get_item("WS-1").unwrap().unwrap().title, "Shared");

        // Independent divergent edits from the shared created event → a fork.
        a.set_field(&issue.id, "title", "from-A").unwrap();
        b.set_field("WS-1", "title", "from-B").unwrap();
        b.import_events(&a.export_events().unwrap()).unwrap();

        let conflicts = b.issue_conflicts("WS-1").unwrap().unwrap();
        assert!(conflicts.conflicted(), "the two writers disagree on title");
        assert_eq!(conflicts.field_conflicts[0].field, "title");
        assert_eq!(
            conflicts.field_conflicts[0].values,
            vec!["from-A", "from-B"]
        );
        assert!(
            WorkItems::ready_items(&b, "q").unwrap().is_empty(),
            "a conflicted issue is not ready on the edge host"
        );

        // Comments/evidence also merge and survive the rebuild the import runs.
        a.add_comment(&issue.id, Some("worker"), "note").unwrap();
        a.add_evidence(&issue.id, Some("log"), Some("s3://x"), None, None)
            .unwrap();
        b.import_events(&a.export_events().unwrap()).unwrap();
        assert_eq!(b.comments("WS-1").unwrap().len(), 1);
        assert_eq!(b.evidence("WS-1").unwrap().len(), 1);
    }

    #[test]
    fn do_coordination_lease_ledger_counter_over_dosql() {
        let mut store = store();
        // Lease: a 1-slot resource holds the first acquirer; a second contends.
        assert_eq!(
            Coordination::try_acquire_for_owner(&mut store, "shared", "r", "k", 1, 600, "h1")
                .expect("acquire"),
            AcquireOutcome::Held
        );
        match Coordination::try_acquire_for_owner(&mut store, "shared", "r", "k", 1, 600, "h2")
            .expect("contend")
        {
            AcquireOutcome::Contended { holders } => assert_eq!(holders, vec!["h1".to_owned()]),
            other => panic!("expected contention, got {other:?}"),
        }
        // Re-acquire by the current holder is idempotent (Held).
        assert_eq!(
            Coordination::try_acquire_for_owner(&mut store, "shared", "r", "k", 1, 600, "h1")
                .expect("reacquire"),
            AcquireOutcome::Held
        );
        assert!(
            Coordination::release_for_owner(&mut store, "shared", "r", "k", "h1").expect("rel")
        );

        // Ledger: appends mint monotonic sequence numbers.
        assert_eq!(
            Coordination::append_for_owner(&mut store, "shared", "log", "p", "{}", "w", 3600)
                .expect("a0"),
            1
        );
        assert_eq!(
            Coordination::append_for_owner(&mut store, "shared", "log", "p", "{}", "w", 3600)
                .expect("a1"),
            2
        );
        assert_eq!(
            Coordination::list_entries_for_owner(&store, Some("shared"), Some("log"), None)
                .expect("entries")
                .len(),
            2
        );

        // Counter: consume under the cap succeeds; over the cap reports Over.
        match Coordination::consume_for_owner(&mut store, "shared", "c", "k", 2, 3, "2030-01-01")
            .expect("consume")
        {
            ConsumeOutcome::Ok { remaining } => assert_eq!(remaining, 1),
            other => panic!("expected Ok, got {other:?}"),
        }
        match Coordination::consume_for_owner(&mut store, "shared", "c", "k", 2, 3, "2030-01-01")
            .expect("consume over")
        {
            ConsumeOutcome::Over { remaining } => assert_eq!(remaining, 1),
            other => panic!("expected Over, got {other:?}"),
        }
        // A rolled period lazily resets the count.
        match Coordination::consume_for_owner(&mut store, "shared", "c", "k", 1, 3, "2030-01-02")
            .expect("consume next period")
        {
            ConsumeOutcome::Ok { remaining } => assert_eq!(remaining, 2),
            other => panic!("expected Ok after reset, got {other:?}"),
        }
    }

    /// DR-0062 §6 provider-trust evidence, DO parity: the same four operations
    /// against the DO's own engine, keyed the same way. The native mirror is
    /// `provider_trust_evidence_records_pin_claim_and_operator_run`; the two
    /// must move together.
    #[test]
    fn do_store_records_provider_trust_evidence() {
        let store = store();

        assert_eq!(
            store
                .provider_trust_evidence("agent_turn", "acme")
                .expect("read"),
            None,
            "no row is the floor, not an error"
        );

        store
            .pin_provider_endpoint("agent_turn", "acme", "sha256:dA")
            .expect("pin");
        store
            .file_provider_custody_claim(ProviderCustodyClaim {
                effect_kind: "agent_turn",
                provider: "acme",
                class: "zero-retention",
                signer: "ops@acme.com",
                filed_at: "2026-08-07T00:00:00Z",
                expires_at: "2027-08-07T00:00:00Z",
            })
            .expect("claim");
        store
            .set_provider_operator_run("agent_turn", "acme", true)
            .expect("operator run");

        let row = store
            .provider_trust_evidence("agent_turn", "acme")
            .expect("read")
            .expect("row exists");
        assert_eq!(row.pinned_digest.as_deref(), Some("sha256:dA"));
        assert_eq!(row.claim_class.as_deref(), Some("zero-retention"));
        assert_eq!(row.claim_signer.as_deref(), Some("ops@acme.com"));
        assert_eq!(
            row.claim_expires_at.as_deref(),
            Some("2027-08-07T00:00:00Z")
        );
        assert!(row.operator_run);

        // Re-pinning leaves the filed claim standing, as natively.
        store
            .pin_provider_endpoint("agent_turn", "acme", "sha256:dB")
            .expect("re-pin");
        let repinned = store
            .provider_trust_evidence("agent_turn", "acme")
            .expect("read")
            .expect("row exists");
        assert_eq!(repinned.pinned_digest.as_deref(), Some("sha256:dB"));
        assert_eq!(repinned.claim_class.as_deref(), Some("zero-retention"));

        assert_eq!(
            store
                .provider_trust_evidence("agent_turn", "other")
                .expect("read"),
            None
        );
    }

    /// The ported core methods run their real SQL against a real engine.
    #[test]
    fn do_store_core_methods_run_real_sql() {
        let store = store();

        assert_eq!(store.schema_version().expect("version"), 2);
        assert!(!store.fact_exists("i1", "ready").expect("fact"));

        let event = store
            .append_event(NewEvent {
                instance_id: "i1",
                event_type: "workflow.started",
                payload_json: "{}",
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("k1"),
            })
            .expect("append");
        assert!(event.event_id.starts_with("evt_"));
        assert_eq!(event.sequence, 1);

        // A second event on the same instance advances the per-instance sequence.
        let event2 = store
            .append_event(NewEvent {
                instance_id: "i1",
                event_type: "effect.claimed",
                payload_json: "{}",
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .expect("append 2");
        assert_eq!(event2.sequence, 2);

        // fact_exists reflects a fact row.
        store
            .sql
            .execute(
                "INSERT INTO facts (instance_id, name) VALUES (?1, ?2)",
                &[text("i1"), text("ready")],
            )
            .expect("insert fact");
        assert!(store.fact_exists("i1", "ready").expect("fact"));

        // register_package runs its real INSERT ... ON CONFLICT and validates JSON.
        store
            .register_package(PackageRegistration {
                package_id: "pkg_1",
                name: "std",
                version: "1.0.0",
                manifest_json: "{}",
            })
            .expect("register");
        let rows = store
            .sql
            .query(
                "SELECT name FROM package_registrations WHERE package_id = ?1",
                &[text("pkg_1")],
            )
            .expect("read package");
        assert_eq!(as_text(&rows[0][0]), "std");
    }

    /// The ported registration methods run their real INSERT...ON CONFLICT SQL.
    #[test]
    fn do_store_registration_methods_run_real_sql() {
        let store = store();

        store
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "std.files",
                description: "file access",
                schema_json: "{}",
                registered_by_package_id: Some("pkg_1"),
            })
            .expect("cap schema");
        store
            .register_effect_provider(EffectProviderRegistration {
                provider_id: "prov_1",
                effect_kind: "schema.coerce",
                provider: "anthropic",
                capability: "std.model",
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("provider");
        store
            .register_profile(ProfileRegistration {
                profile_id: "prof_1",
                name: "default",
                description: "d",
                enforcement_mode: "enforce",
                allowed_capabilities_json: "[]",
                config_json: "{}",
            })
            .expect("profile");
        store
            .bind_capability(CapabilityBinding {
                binding_id: "bind_1",
                program_id: Some("prg_1"),
                capability: "std.files",
                provider: "local",
                config_json: "{}",
            })
            .expect("binding");

        for (table, key_col, key) in [
            ("capability_schemas", "capability", "std.files"),
            ("effect_providers", "provider_id", "prov_1"),
            ("profiles", "profile_id", "prof_1"),
            ("capability_bindings", "binding_id", "bind_1"),
        ] {
            let rows = store
                .sql
                .query(
                    &format!("SELECT 1 FROM {table} WHERE {key_col} = ?1"),
                    &[text(key)],
                )
                .expect("read");
            assert_eq!(rows.len(), 1, "{table} row present");
        }
    }

    /// Skills, inbox items, fact retirement, and table_exists run their real SQL
    /// and round-trip through the ported view mappers.
    #[test]
    fn do_store_skills_and_facts_run_real_sql() {
        let mut store = store();

        // register_skill validates JSON, computes content_hash, upserts by name;
        // attach_skill resolves skill_id and links a scope; the views round-trip.
        store
            .register_skill(SkillRegistration {
                skill_id: "skl_1",
                name: "triage",
                version: "1.0.0",
                source: "fs",
                source_path: "skills/triage.md",
                body: "# Triage\nTriage the inbox.\n",
                description: "triage inbox",
                required_capabilities_json: "[]",
                metadata_json: "{}",
            })
            .expect("register_skill");
        // content_hash is the hash of the body (Decision 3), matching the native store.
        assert_eq!(
            stable_hash_hex("# Triage\nTriage the inbox.\n"),
            store.list_skills().expect("list_skills")[0].content_hash,
        );

        store
            .attach_skill(SkillAttachment {
                attachment_id: "att_1",
                scope_type: "instance",
                scope_id: "i1",
                skill_name: "triage",
            })
            .expect("attach_skill");
        // Idempotent re-attach is a no-op (ON CONFLICT DO NOTHING).
        store
            .attach_skill(SkillAttachment {
                attachment_id: "att_2",
                scope_type: "instance",
                scope_id: "i1",
                skill_name: "triage",
            })
            .expect("attach_skill again");
        let attachments = store
            .list_skill_attachments("instance", "i1")
            .expect("list_skill_attachments");
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].skill.name, "triage");

        // Attaching an unknown skill errors (native query_row would find no row).
        assert!(store
            .attach_skill(SkillAttachment {
                attachment_id: "att_3",
                scope_type: "instance",
                scope_id: "i1",
                skill_name: "missing",
            })
            .is_err());

        // retire_fact marks an unconsumed fact consumed; a second call is a no-op.
        store
            .sql
            .execute(
                "INSERT INTO facts (fact_id, instance_id, name) VALUES (?1, ?2, ?3)",
                &[text("f1"), text("i1"), text("ready")],
            )
            .expect("insert fact");
        store.retire_fact("i1", "f1").expect("retire");
        let consumed = store
            .sql
            .query(
                "SELECT consumed_at FROM facts WHERE fact_id = ?1",
                &[text("f1")],
            )
            .expect("read fact");
        assert!(matches!(consumed[0][0], SqlValue::Text(_)));

        // table_exists reflects the schema.
        assert!(!store.table_exists("no_such_table").expect("absent"));
    }

    /// The instance/event/fact/effect/run read-query family runs its real SQL
    /// (including the effect/run join + EXISTS cancel-requested flag) and decodes
    /// rows through the ported view mappers.
    #[test]
    fn do_store_read_query_family_runs_real_sql() {
        let store = store();
        let e = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);

        e(
            "INSERT INTO program_versions (version_id, declared_profiles) VALUES (?1, ?2)",
            &[text("ver_1"), text("[\"p\"]")],
        );
        e(
            "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
             workflow_principal, effective_authority, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                text("i1"),
                text("prog_1"),
                text("ver_1"),
                int(3),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );
        e(
            "INSERT INTO events (event_id, instance_id, sequence, event_type, payload_json, \
             occurred_at, source) VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, ?6)",
            &[
                text("evt_a"),
                text("i1"),
                int(1),
                text("started"),
                text("{}"),
                text("kernel"),
            ],
        );
        e(
            "INSERT INTO facts (fact_id, instance_id, program_version_id, revision_epoch, name, \
             key, value_json, provenance_class) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                text("f_live"),
                text("i1"),
                text("ver_1"),
                int(0),
                text("ready"),
                text(""),
                text("true"),
                text("derived"),
            ],
        );
        e(
            "INSERT INTO facts (fact_id, instance_id, name, provenance_class, consumed_at) \
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            &[text("f_gone"), text("i1"), text("done"), text("derived")],
        );
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, target, status, program_version_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[text("eff_1"), text("i1"), text("schema.coerce"), SqlValue::Null, text("queued"), text("ver_1")],
        );
        e(
            "INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status, \
             started_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)",
            &[
                text("run_1"),
                text("i1"),
                text("eff_1"),
                text("anthropic"),
                text("w1"),
                text("running"),
            ],
        );
        e(
            "INSERT INTO effect_cancellation_requests (instance_id, effect_id, status) \
             VALUES (?1, ?2, ?3)",
            &[text("i1"), text("eff_1"), text("requested")],
        );

        let instances = store.list_instances().expect("list_instances");
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].revision_epoch, 3);
        assert_eq!(instances[0].workflow_principal, "root");
        assert_eq!(
            store.get_instance("i1").expect("get").expect("some").status,
            "running"
        );
        assert!(store
            .get_instance("missing")
            .expect("get missing")
            .is_none());

        let events = store.list_events("i1").expect("list_events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 1);

        // list_facts hides the consumed fact; the "including" variant shows both.
        let live = store.list_facts("i1").expect("list_facts");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "ready");
        assert_eq!(live[0].program_version_id.as_deref(), Some("ver_1"));
        assert_eq!(
            store
                .list_facts_including_consumed("i1")
                .expect("incl")
                .len(),
            2
        );

        // list_effects joins declared_profiles and computes cancel_requested via EXISTS.
        let effects = store.list_effects("i1").expect("list_effects");
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].target, None);
        assert_eq!(effects[0].declared_profiles_json, "[\"p\"]");
        assert!(effects[0].cancel_requested);

        let runs = store.list_runs("i1").expect("list_runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].provider, "anthropic");
        assert!(runs[0].cancel_requested);
    }

    /// Revisions, cancellation-request reads, workflow-invocation record/read (with
    /// the parent/child join), and the composite `status` view all run real SQL.
    #[test]
    fn do_store_revisions_invocations_and_status_run_real_sql() {
        let store = store();
        let e = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);

        // Two instances (parent + child) and a version.
        e(
            "INSERT INTO program_versions (version_id, declared_profiles) VALUES (?1, ?2)",
            &[text("ver_1"), text("[]")],
        );
        for id in ["parent", "child"] {
            e(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text(id),
                    text("prog_1"),
                    text("ver_1"),
                    int(1),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            );
        }
        // A parent invoke-effect that the invocation points at.
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, program_version_id, \
             revision_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("eff_inv"),
                text("parent"),
                text("workflow.invoke"),
                text("running"),
                text("ver_1"),
                int(1),
            ],
        );

        // A revision row round-trips.
        e(
            "INSERT INTO instance_revisions (revision_id, instance_id, epoch, from_version_id, \
             to_version_id, activated_by_event_id, cancellation_policy, status, activated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                text("rev_1"),
                text("parent"),
                int(1),
                text("ver_0"),
                text("ver_1"),
                text("evt_x"),
                text("keep"),
                text("activated"),
                text("2026-01-01T00:00:00Z"),
            ],
        );
        let revisions = store.list_instance_revisions("parent").expect("revisions");
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].to_version_id, "ver_1");

        // A cancellation request round-trips and the open-check sees it.
        e(
            "INSERT INTO effect_cancellation_requests (request_id, instance_id, effect_id, \
             requested_by, status) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("req_1"),
                text("parent"),
                text("eff_inv"),
                text("kernel"),
                text("requested"),
            ],
        );
        assert!(store
            .effect_has_open_cancellation_request("parent", "eff_inv")
            .expect("open?"));
        assert!(!store
            .effect_has_open_cancellation_request("parent", "other")
            .expect("open?"));
        assert_eq!(
            store
                .list_effect_cancellation_requests("parent")
                .expect("list reqs")
                .len(),
            1
        );

        // record_workflow_invocation resolves parent effect + child instance versions.
        store
            .record_workflow_invocation(NewWorkflowInvocation {
                invocation_id: "inv_1",
                parent_instance_id: "parent",
                parent_effect_id: "eff_inv",
                child_instance_id: "child",
                target_workflow: "sub",
                input_json: "{}",
                source_span_json: None,
                idempotency_key: "idem_1",
            })
            .expect("record invocation");
        // Idempotent replay is a no-op (ON CONFLICT(idempotency_key) DO NOTHING).
        store
            .record_workflow_invocation(NewWorkflowInvocation {
                invocation_id: "inv_2",
                parent_instance_id: "parent",
                parent_effect_id: "eff_inv",
                child_instance_id: "child",
                target_workflow: "sub",
                input_json: "{}",
                source_span_json: None,
                idempotency_key: "idem_1",
            })
            .expect("replay invocation");

        let got = store
            .get_workflow_invocation("parent", "eff_inv")
            .expect("get inv")
            .expect("some");
        assert_eq!(got.invocation_id, "inv_1");
        assert_eq!(got.child_instance_id, "child");
        assert_eq!(
            got.child_active_program_version_id.as_deref(),
            Some("ver_1")
        );
        assert_eq!(got.parent_active_revision_epoch, Some(1));

        assert_eq!(
            store
                .list_child_workflow_invocations("parent")
                .expect("children")
                .len(),
            1
        );
        assert_eq!(
            store
                .get_parent_workflow_invocation("child")
                .expect("parent inv")
                .expect("some")
                .invocation_id,
            "inv_1"
        );

        // The composite status view assembles counts + reads.
        e(
            "INSERT INTO facts (fact_id, instance_id, name, provenance_class) \
             VALUES (?1, ?2, ?3, ?4)",
            &[text("f1"), text("parent"), text("ready"), text("derived")],
        );
        let status = store.status("parent").expect("status").expect("some");
        assert_eq!(status.instance.instance_id, "parent");
        assert_eq!(status.fact_count, 1);
        assert_eq!(status.cancellation_request_count, 1);
        assert_eq!(status.revisions.len(), 1);
        assert_eq!(status.child_invocations.len(), 1);
        assert!(store.status("ghost").expect("missing status").is_none());
    }

    /// The program-version / instance-create / profile-policy / workspace /
    /// artifact / diagnostic / evidence read+record family runs real SQL.
    #[test]
    fn do_store_program_workspace_diagnostic_evidence_run_real_sql() {
        let store = store();
        let e = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);

        // get_program_version joins programs.name.
        e(
            "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
            &[text("prog_1"), text("orders")],
        );
        e(
            "INSERT INTO program_versions (version_id, program_id, source_hash, ir_hash, \
             compiler_version, analysis_summary) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("ver_1"),
                text("prog_1"),
                text("sh"),
                text("ih"),
                text("1.0"),
                text("{}"),
            ],
        );
        let pv = store
            .get_program_version("ver_1")
            .expect("get pv")
            .expect("some");
        assert_eq!(pv.program_name, "orders");
        assert!(store.get_program_version("nope").expect("none").is_none());

        // create_instance mints an ins_ id via RETURNING and defaults status=running.
        let rec = store
            .create_instance(NewInstance {
                program_id: "prog_1",
                version_id: "ver_1",
                input_json: "{}",
            })
            .expect("create_instance");
        assert!(rec.instance_id.starts_with("ins_"));
        assert_eq!(rec.status, "running");
        assert_eq!(
            store
                .get_instance(&rec.instance_id)
                .expect("get")
                .expect("some")
                .status,
            "running"
        );

        // registered_profile_policy decodes the allowed-capabilities JSON array.
        store
            .register_profile(ProfileRegistration {
                profile_id: "prof_1",
                name: "guarded",
                description: "d",
                enforcement_mode: "enforce",
                allowed_capabilities_json: "[\"std.files\",\"std.model\"]",
                config_json: "{}",
            })
            .expect("register_profile");
        let policy = store
            .registered_profile_policy("guarded")
            .expect("policy")
            .expect("some");
        assert_eq!(policy.enforcement_mode, "enforce");
        assert_eq!(policy.allowed_capabilities, vec!["std.files", "std.model"]);
        assert!(store
            .registered_profile_policy("absent")
            .expect("none")
            .is_none());

        // record_workspace upserts (RETURNING id) and validates policy/status/metadata;
        // a re-record with the same conflict key returns the same id.
        let ws_id = store
            .record_workspace(WorkspaceRecord {
                instance_id: Some("i1"),
                effect_id: Some("eff_1"),
                run_id: Some("run_1"),
                provider: Some("git"),
                policy: "per_effect_worktree",
                uri: "file:///w",
                status: "active",
                metadata_json: "{}",
            })
            .expect("record_workspace");
        let ws_id2 = store
            .record_workspace(WorkspaceRecord {
                instance_id: Some("i1"),
                effect_id: Some("eff_1"),
                run_id: Some("run_1"),
                provider: Some("git"),
                policy: "per_effect_worktree",
                uri: "file:///w2",
                status: "released",
                metadata_json: "{}",
            })
            .expect("re-record");
        assert_eq!(ws_id, ws_id2);
        assert_eq!(
            store
                .get_workspace(&ws_id)
                .expect("get")
                .expect("some")
                .status,
            "released"
        );
        assert_eq!(
            store
                .list_workspaces_for_instance("i1")
                .expect("list")
                .len(),
            1
        );
        // A bad policy is rejected before touching SQL.
        assert!(store
            .record_workspace(WorkspaceRecord {
                instance_id: Some("i1"),
                effect_id: None,
                run_id: None,
                provider: None,
                policy: "bogus",
                uri: "file:///x",
                status: "active",
                metadata_json: "{}",
            })
            .is_err());

        // list_artifacts_for_run.
        e(
            "INSERT INTO artifacts (artifact_id, run_id, kind, path, content_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("art_1"),
                text("run_1"),
                text("log"),
                text("/l"),
                SqlValue::Null,
            ],
        );
        let artifacts = store.list_artifacts_for_run("run_1").expect("artifacts");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].content_hash, None);

        // list_diagnostics (stored table) + list_diagnostics_from_events (event JSON).
        e(
            "INSERT INTO diagnostics (diagnostic_id, instance_id, severity, message) \
             VALUES (?1, ?2, ?3, ?4)",
            &[text("dia_1"), text("i1"), text("error"), text("boom")],
        );
        assert_eq!(store.list_diagnostics(Some("i1")).expect("diag").len(), 1);
        assert_eq!(store.list_diagnostics(None).expect("all diag").len(), 1);
        e(
            "INSERT INTO events (event_id, instance_id, sequence, event_type, payload_json, \
             occurred_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("evt_term"),
                text("i1"),
                int(1),
                text("effect.terminal"),
                text("{\"effect_id\":\"eff_1\",\"diagnostic\":{\"severity\":\"warning\",\"message\":\"m\"}}"),
                text("2026-01-01T00:00:00Z"),
                text("kernel"),
            ],
        );
        let from_events = store
            .list_diagnostics_from_events("i1")
            .expect("diag from events");
        assert_eq!(from_events.len(), 1);
        assert_eq!(from_events[0].severity, "warning");
        assert_eq!(from_events[0].effect_id.as_deref(), Some("eff_1"));

        // effect_source_span_json digs the span out of the creating event's payload.
        e(
            "INSERT INTO events (event_id, instance_id, sequence, event_type, payload_json, \
             occurred_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("evt_create"),
                text("i1"),
                int(2),
                text("rule.committed"),
                text("{\"effects\":[{\"effect_id\":\"eff_1\",\"source_span\":{\"line\":4}}]}"),
                text("2026-01-01T00:00:01Z"),
                text("kernel"),
            ],
        );
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, created_by_event_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_1"),
                text("i1"),
                text("schema.coerce"),
                text("queued"),
                text("evt_create"),
            ],
        );
        assert_eq!(
            store
                .effect_source_span_json("i1", "eff_1")
                .expect("span")
                .as_deref(),
            Some("{\"line\":4}")
        );
        assert!(store
            .effect_source_span_json("i1", "missing")
            .expect("no span")
            .is_none());

        // Evidence + evidence links.
        e(
            "INSERT INTO evidence (evidence_id, instance_id, kind, subject_type, subject_id, \
             summary) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("ev_1"),
                text("i1"),
                text("provider_validation"),
                text("effect"),
                text("eff_1"),
                text("ok"),
            ],
        );
        e(
            "INSERT INTO evidence_links (evidence_id, instance_id, target_type, target_id, relation) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[text("ev_1"), text("i1"), text("effect"), text("eff_1"), text("supports")],
        );
        assert_eq!(store.list_evidence("i1").expect("evidence").len(), 1);
        assert_eq!(
            store
                .list_evidence_for_subject("effect", "eff_1")
                .expect("subject")
                .len(),
            1
        );
        assert_eq!(
            store.list_evidence_links("i1").expect("links")[0].relation,
            "supports"
        );
    }

    /// The evidence/diagnostic/artifact *record* family runs real INSERT...RETURNING
    /// SQL (plus the derived evidence-link fan-out) and is idempotent where the
    /// native path is.
    #[test]
    fn do_store_record_evidence_diagnostic_artifact_run_real_sql() {
        use whipplescript_core::Severity;
        let store = store();

        // A skill to inject, so record_skill_evidence resolves it.
        store
            .register_skill(SkillRegistration {
                skill_id: "skl_1",
                name: "triage",
                version: "2.0.0",
                source: "fs",
                source_path: "p",
                body: "# Triage\n",
                description: "",
                required_capabilities_json: "[]",
                metadata_json: "{}",
            })
            .expect("register_skill");

        // record_evidence mints evd_ id and fans out a "subject" + causation link.
        let ev_id = store
            .record_evidence(EvidenceRecord {
                instance_id: "i1",
                kind: "note",
                subject_type: "effect",
                subject_id: "eff_1",
                causation_id: Some("cause_1"),
                correlation_id: None,
                summary: Some("s"),
                metadata_json: "{}",
            })
            .expect("record_evidence");
        assert!(ev_id.starts_with("evd_"));
        let links = store.list_evidence_links("i1").expect("links");
        assert!(links.iter().any(|l| l.relation == "subject"));
        assert!(links.iter().any(|l| l.relation == "caused_by"));

        // link_evidence is idempotent on its natural key.
        for _ in 0..2 {
            store
                .link_evidence(EvidenceLink {
                    evidence_id: &ev_id,
                    instance_id: "i1",
                    target_type: "extra",
                    target_id: "x",
                    relation: "rel",
                })
                .expect("link_evidence");
        }
        assert_eq!(
            store
                .list_evidence_links("i1")
                .expect("links")
                .iter()
                .filter(|l| l.relation == "rel")
                .count(),
            1
        );

        // Provider-validation evidence records the row + two typed links.
        let pv_id = store
            .record_provider_validation_evidence(ProviderValidationEvidence {
                instance_id: "i1",
                provider_id: "prov_1",
                provider_kind: "anthropic",
                surface: "model",
                status: "passed",
                config_json: "{}",
                capability_json: "{}",
                validation_results_json: "[]",
                source_path: None,
                correlation_id: None,
            })
            .expect("provider validation");
        assert!(pv_id.starts_with("evd_"));

        // record_skill_evidence resolves the skill + records injected-skills evidence.
        let se_id = store
            .record_skill_evidence(SkillEvidence {
                instance_id: "i1",
                run_id: "run_1",
                effect_id: "eff_1",
                skill_names: &["triage"],
                idempotency_key: Some("idem"),
            })
            .expect("skill evidence");
        assert!(se_id.starts_with("evd_"));

        // record_artifact mints art_ id.
        let art_id = store
            .record_artifact(ArtifactRecord {
                run_id: "run_1",
                kind: "log",
                path: "/l",
                content_hash: Some("h"),
                mime_type: None,
            })
            .expect("record_artifact");
        assert!(art_id.starts_with("art_"));

        // record_diagnostic mints dia_ id; a second call with the same idempotency
        // key returns the same id (no duplicate row).
        let make = || DiagnosticRecord {
            instance_id: Some("i1"),
            program_id: None,
            program_version_id: None,
            severity: Severity::Error,
            code: Some("E1"),
            message: "boom",
            source_span_json: None,
            subject_type: None,
            subject_id: None,
            event_id: None,
            effect_id: None,
            run_id: None,
            assertion_id: None,
            evidence_ids_json: "[]",
            artifact_ids_json: "[]",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("diag-idem"),
        };
        let d1 = store.record_diagnostic(make()).expect("diag 1");
        let d2 = store.record_diagnostic(make()).expect("diag 2");
        assert_eq!(d1, d2);
        assert_eq!(store.list_diagnostics(Some("i1")).expect("diag").len(), 1);
        // A non-array evidence_ids_json is rejected.
        let mut bad = make();
        bad.evidence_ids_json = "{}";
        assert!(store.record_diagnostic(bad).is_err());
    }

    /// The clock/time-obligation and dependency-satisfaction queries run their real
    /// (strftime / recursive-CTE / dependency-predicate) SQL.
    #[test]
    fn do_store_clock_time_and_dependencies_run_real_sql() {
        let store = store();
        let e = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);

        // resolve_clock normalizes an instant; a garbage token errors.
        assert_eq!(
            store.resolve_clock("2026-01-02T03:04:05Z").expect("clock"),
            "2026-01-02T03:04:05Z"
        );
        assert!(store.resolve_clock("not-a-time").is_err());

        // due_interval_occurrences is pure interval arithmetic.
        let occ = store
            .due_interval_occurrences("2026-01-01T00:00:00Z", 3600, "2026-01-01T02:00:00Z")
            .expect("occurrences");
        assert_eq!(
            occ,
            vec![
                "2026-01-01T01:00:00Z".to_string(),
                "2026-01-01T02:00:00Z".to_string()
            ]
        );
        assert!(store
            .due_interval_occurrences("2026-01-01T00:00:00Z", 0, "2026-01-01T02:00:00Z")
            .expect("no interval")
            .is_empty());

        // An effect whose creation-anchored timeout has elapsed is due; pending lists it too.
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, \
             timeout_seconds, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("eff_timeout"),
                text("i1"),
                text("timer.wait"),
                text("queued"),
                text("{}"),
                int(60),
                text("2026-01-01T00:00:00Z"),
            ],
        );
        let due = store
            .due_time_effects("i1", "2026-01-01T00:05:00Z")
            .expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].effect_id, "eff_timeout");
        assert_eq!(due[0].timeout_seconds, 60);
        // Not yet due at t+30s.
        assert!(store
            .due_time_effects("i1", "2026-01-01T00:00:30Z")
            .expect("not due")
            .is_empty());
        assert_eq!(store.pending_time_effects("i1").expect("pending").len(), 1);

        // last_clock_occurrence reads MAX(scheduled_at) from matching events.
        e(
            "INSERT INTO events (event_id, instance_id, sequence, event_type, payload_json, \
             occurred_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("evt_c"),
                text("i1"),
                int(1),
                text("clock.tick"),
                text("{\"scheduled_at\":\"2026-01-01T01:00:00Z\"}"),
                text("2026-01-01T01:00:00Z"),
                text("kernel"),
            ],
        );
        assert_eq!(
            store
                .last_clock_occurrence("i1", "clock.tick")
                .expect("last")
                .as_deref(),
            Some("2026-01-01T01:00:00Z")
        );
        assert!(store
            .last_clock_occurrence("i1", "absent")
            .expect("none")
            .is_none());

        // satisfy_dependencies queues an effect once its upstream succeeds.
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("up"),
                text("i1"),
                text("schema.coerce"),
                text("completed"),
                text("{}"),
            ],
        );
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("down"),
                text("i1"),
                text("schema.coerce"),
                text("blocked_by_dependency"),
                text("{}"),
            ],
        );
        e(
            "INSERT INTO effect_dependencies (instance_id, downstream_effect_id, \
             upstream_effect_id, predicate) VALUES (?1, ?2, ?3, ?4)",
            &[text("i1"), text("down"), text("up"), text("succeeds")],
        );
        assert_eq!(store.satisfy_dependencies("i1").expect("satisfy"), 1);
        let down_status = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("down")],
            )
            .expect("read");
        assert_eq!(as_text(&down_status[0][0]), "queued");
    }

    /// The DO alarm scheduler (`next_effect_due_epoch_ms`) must report a due
    /// instant ONLY for a timer.wait `advance_time` can actually fire — i.e.
    /// not one still blocked on an unsatisfied upstream dependency. Otherwise
    /// the shell schedules an alarm for a creation-anchored deadline already in
    /// the past, Cloudflare runs it instantly, and the re-drive/re-park cycle
    /// busy-loops. This mirrors the `due_time_effects` dep guard.
    #[test]
    fn next_due_omits_a_dependency_blocked_timer() {
        let store = store();
        let e = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        // An upstream coerce that has not resolved yet (still queued).
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("ask"),
                text("i1"),
                text("schema.coerce"),
                text("queued"),
                text("{}"),
            ],
        );
        // A timer.wait created at t0 with a 30s timeout, blocked on the ask.
        e(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, \
             timeout_seconds, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("wait"),
                text("i1"),
                text("timer.wait"),
                text("blocked_by_dependency"),
                text("{}"),
                int(30),
                text("2026-01-01T00:00:00Z"),
            ],
        );
        e(
            "INSERT INTO effect_dependencies (instance_id, downstream_effect_id, \
             upstream_effect_id, predicate) VALUES (?1, ?2, ?3, ?4)",
            &[text("i1"), text("wait"), text("ask"), text("succeeds")],
        );
        // While the ask is unsatisfied the blocked timer contributes no due
        // instant — no alarm to busy-loop on.
        assert_eq!(
            store.next_effect_due_epoch_ms("i1").expect("next due"),
            None,
            "a dependency-blocked timer.wait must not be reported as due"
        );
        // Once the upstream succeeds the timer is fireable, so its creation-
        // anchored deadline (t0 + 30s) is reported.
        store
            .sql
            .execute(
                "UPDATE effects SET status = 'completed' WHERE effect_id = ?1",
                &[text("ask")],
            )
            .expect("complete ask");
        // 2026-01-01T00:00:00Z = 1767225600s; + 30s timeout, in milliseconds.
        let expected = (1_767_225_600_i64 + 30) * 1000;
        assert_eq!(
            store.next_effect_due_epoch_ms("i1").expect("next due"),
            Some(expected),
            "an unblocked timer.wait reports its deadline"
        );
    }

    /// The event-plus-update lifecycle methods (transition_instance,
    /// block_effect_binding, expire_effect) run
    /// their real event-append + update SQL and enforce their guards.
    #[test]
    fn do_store_lifecycle_transitions_run_real_sql() {
        let mut store = store();
        // These methods take `&mut self`, so seed rows via direct short-lived
        // `store.sql.execute` calls rather than a borrow-holding closure.
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
                 effective_authority, status, input_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    text("i1"),
                    text("p"),
                    text("v"),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        // transition_instance: running -> paused is allowed and records an event +
        // sets last_event_id; a disallowed jump errors.
        let ev = store
            .transition_instance(InstanceTransition {
                instance_id: "i1",
                status: "paused",
                reason: Some("halt"),
                idempotency_key: None,
            })
            .expect("transition");
        assert!(ev.event_id.starts_with("evt_"));
        let inst = store.get_instance("i1").expect("get").expect("some");
        assert_eq!(inst.status, "paused");
        // paused -> completed is not an allowed transition.
        assert!(store
            .transition_instance(InstanceTransition {
                instance_id: "i1",
                status: "completed",
                reason: None,
                idempotency_key: None,
            })
            .is_err());

        // block_effect_binding: first call records; a second call with the same
        // category returns the SAME event (idempotent) without a new row.
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text("eff_1"),
                    text("i1"),
                    text("schema.coerce"),
                    text("queued"),
                    text("{}"),
                ],
            )
            .expect("seed eff_1");
        let b1 = store
            .block_effect_binding("i1", "eff_1", "credentials", "no token")
            .expect("block");
        let b2 = store
            .block_effect_binding("i1", "eff_1", "credentials", "no token")
            .expect("block again");
        assert_eq!(b1.event_id, b2.event_id);
        let blocked = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read");
        assert_eq!(as_text(&blocked[0][0]), "blocked");

        // expire_effect times out a live effect; a second expire errors (guarded).
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text("eff_t"),
                    text("i1"),
                    text("timer.wait"),
                    text("queued"),
                    text("{}"),
                ],
            )
            .expect("seed eff_t");
        store.expire_effect("i1", "eff_t", None).expect("expire");
        assert!(store.expire_effect("i1", "eff_t", None).is_err());
    }

    /// derive_fact and admit_fact_batch append a `fact.derived` event and insert the
    /// fact row(s); the batch is idempotent on the per-row `fact_id`.
    #[test]
    fn do_store_fact_derivation_runs_real_sql() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(2),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        // derive_fact stamps the active (version, epoch) onto the fact row.
        let ev = store
            .derive_fact(DerivedFact {
                instance_id: "i1",
                fact: NewFact {
                    fact_id: "fct_1",
                    name: "ready",
                    key: "k",
                    value_json: "true",
                    schema_id: None,
                    provenance_class: "derived",
                    correlation_id: None,
                    source_span_json: None,
                },
                source: "rule.a",
                causation_id: None,
                idempotency_key: Some("d1"),
            })
            .expect("derive_fact");
        assert!(ev.event_id.starts_with("evt_"));
        let facts = store.list_facts("i1").expect("facts");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].program_version_id.as_deref(), Some("ver_1"));
        assert_eq!(facts[0].revision_epoch, 2);

        // admit_fact_batch admits new rows; re-admitting the same fact_ids is skipped.
        let rows = [
            FactBatchRow {
                fact_id: "row_1",
                key: "a",
                value_json: "1",
            },
            FactBatchRow {
                fact_id: "row_2",
                key: "b",
                value_json: "2",
            },
        ];
        let out = store
            .admit_fact_batch(FactBatch {
                instance_id: "i1",
                source: "import.x",
                causation_id: None,
                correlation_id: None,
                schema_name: "Order",
                schema_id: Some("sch_1"),
                rows: &rows,
            })
            .expect("admit");
        assert_eq!(out.admitted, 2);
        assert_eq!(out.skipped, 0);
        let out2 = store
            .admit_fact_batch(FactBatch {
                instance_id: "i1",
                source: "import.x",
                causation_id: None,
                correlation_id: None,
                schema_name: "Order",
                schema_id: Some("sch_1"),
                rows: &rows,
            })
            .expect("re-admit");
        assert_eq!(out2.admitted, 0);
        assert_eq!(out2.skipped, 2);
        // 1 derived + 2 imported = 3 active facts.
        assert_eq!(store.list_facts("i1").expect("facts").len(), 3);
    }

    /// DR-0054 Phase B (native parity): new event rows carry the writer's
    /// format version; a row stamped beyond what this build supports fails the
    /// projection fold closed with its row identity instead of misparsing.
    #[test]
    fn do_future_event_format_version_fails_the_fold_with_row_identity() {
        let mut store = store();
        let version = store
            .create_program_version(NewProgramVersion {
                program_name: "format-guard",
                source_hash: "sh1",
                ir_hash: "ih1",
                compiler_version: "1.0",
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let event = store
            .append_event(NewEvent {
                instance_id: &instance.instance_id,
                event_type: "fact.derived",
                payload_json: r#"{"fact_id":"f1","name":"n","key":"k","value":{}}"#,
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .expect("event appends");

        // The writer stamped its format on the new row.
        let stamped = store
            .sql
            .query(
                "SELECT format_version FROM events WHERE event_id = ?1",
                &[text(&event.event_id)],
            )
            .expect("stamp readable");
        assert_eq!(
            as_opt_i64(&stamped[0][0]),
            Some(whipplescript_store::SUPPORTED_EVENT_FORMAT_VERSION)
        );

        // A NULL (legacy) row folds fine...
        store
            .sql
            .execute(
                "UPDATE events SET format_version = NULL WHERE event_id = ?1",
                &[text(&event.event_id)],
            )
            .expect("regress to legacy NULL");
        store
            .rebuild_projections(&instance.instance_id)
            .expect("legacy NULL rows fold as version 1");

        // ...but a row from a newer format fails the fold closed with identity.
        store
            .sql
            .execute(
                "UPDATE events SET format_version = 99 WHERE event_id = ?1",
                &[text(&event.event_id)],
            )
            .expect("stamp future format");
        let error = store
            .rebuild_projections(&instance.instance_id)
            .expect_err("future-format row must fail the fold");
        match &error {
            StoreError::UnsupportedVersion {
                subject,
                found,
                supported,
            } => {
                assert_eq!(*found, 99);
                assert_eq!(
                    *supported,
                    whipplescript_store::SUPPORTED_EVENT_FORMAT_VERSION
                );
                assert!(
                    subject.contains(&event.event_id) && subject.contains(&instance.instance_id),
                    "subject carries the row identity: {subject}"
                );
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    /// create_program_version upserts a program + version (idempotent on the
    /// content hashes); register_package_manifest fans a manifest out across the
    /// registration tables. Both verified against real SQLite.
    #[test]
    fn do_store_program_and_manifest_registration_run_real_sql() {
        let mut store = store();

        let mk = || NewProgramVersion {
            program_name: "orders",
            source_hash: "sh1",
            ir_hash: "ih1",
            compiler_version: "1.0",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        };
        let rec = store.create_program_version(mk()).expect("create pv");
        assert!(rec.program_id.starts_with("prg_"));
        assert!(rec.version_id.starts_with("ver_"));
        // Idempotent: same name + hashes returns the same ids.
        let rec2 = store.create_program_version(mk()).expect("create pv again");
        assert_eq!(rec, rec2);
        assert_eq!(
            store
                .get_program_version(&rec.version_id)
                .expect("get")
                .expect("some")
                .program_name,
            "orders"
        );

        // register_package_manifest fans out into every registration table.
        let manifest = r#"{
            "package_id": "pkg.demo",
            "name": "demo",
            "version": "0.1.0",
            "capabilities": [{"capability": "demo.read", "description": "read", "schema": {}}],
            "providers": [{"provider_id": "prov.a", "effect_kind": "demo.read",
                           "provider": "local", "capability": "demo.read", "config": {}}],
            "profiles": [{"profile_id": "prof.a", "name": "demo-default",
                          "allowed_capabilities": ["demo.read"], "config": {}}],
            "bindings": [{"binding_id": "bind.a", "capability": "demo.read",
                          "provider": "local", "config": {}}]
        }"#;
        let pkg_id = store
            .register_package_manifest(manifest)
            .expect("register manifest");
        assert_eq!(pkg_id, "pkg.demo");
        for (table, col, key) in [
            ("package_registrations", "package_id", "pkg.demo"),
            ("capability_schemas", "capability", "demo.read"),
            ("effect_providers", "provider_id", "prov.a"),
            ("profiles", "profile_id", "prof.a"),
            ("capability_bindings", "binding_id", "bind.a"),
        ] {
            let rows = store
                .sql
                .query(
                    &format!("SELECT 1 FROM {table} WHERE {col} = ?1"),
                    &[text(key)],
                )
                .expect("read");
            assert_eq!(rows.len(), 1, "{table} populated by manifest");
        }

        // A manifest missing a required field is rejected.
        assert!(store
            .register_package_manifest(r#"{"name": "x", "version": "1"}"#)
            .is_err());
    }

    /// DO package bootstrap (spec/durable-object-runtime-tracker.md): a fresh DO
    /// store has NO provider rows for the coordination/tracker/file/ingress/
    /// coercion kinds, so the admission gate would block them — which is why the
    /// old `do_policy_block_on` exempted them. `register_embedded_std_packages`
    /// seeds the same rows native seeds, making the gate REAL on the DO too, so
    /// the exemptions could be removed (only `timer.wait` stays waved through).
    #[test]
    fn do_package_bootstrap_seeds_admission_rows_for_std_effect_kinds() {
        let store = store();
        let gated_kinds = [
            "lease.acquire",
            "ledger.append",
            "counter.consume",
            "tracker.claim",
            "file.read",
            "signal.emit",
            "schema.coerce",
        ];
        // Before the bootstrap: no provider row → these kinds would block.
        for kind in gated_kinds {
            assert!(
                !do_effect_provider_exists(&store.sql, kind).expect("query"),
                "unbootstrapped DO store must not know provider for `{kind}`"
            );
        }
        crate::do_packages::register_embedded_std_packages(&store).expect("bootstrap");
        // After: every std effect kind has an admission-plane provider row.
        for kind in gated_kinds {
            assert!(
                do_effect_provider_exists(&store.sql, kind).expect("query"),
                "bootstrap must seed a provider for `{kind}` so the gate admits it"
            );
        }
        // Idempotent: a re-attach re-seeding is a no-op, not an error.
        crate::do_packages::register_embedded_std_packages(&store).expect("re-bootstrap");
    }

    /// renew_lease extends an active lease (guarded); expire_leases sweeps expired
    /// leases, recording an event and requeuing the run + effect. Real SQL.
    #[test]
    fn do_store_leases_run_real_sql() {
        let mut store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO leases (lease_id, instance_id, run_id, effect_id, status, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("lse_1"),
                text("i1"),
                text("run_1"),
                text("eff_1"),
                text("active"),
                text("2026-01-01T00:00:00Z"),
            ],
        );
        seed(
            "INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status, \
             started_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)",
            &[
                text("run_1"),
                text("i1"),
                text("eff_1"),
                text("p"),
                text("w"),
                text("running"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_1"),
                text("i1"),
                text("schema.coerce"),
                text("running"),
                text("{}"),
            ],
        );

        // renew_lease pushes expires_at forward for the active lease.
        store
            .renew_lease(LeaseRenewal {
                instance_id: "i1",
                lease_id: "lse_1",
                run_id: "run_1",
                new_expires_at: "2026-01-01T01:00:00Z",
                idempotency_key: None,
            })
            .expect("renew");
        // Renewing an unknown lease errors.
        assert!(store
            .renew_lease(LeaseRenewal {
                instance_id: "i1",
                lease_id: "nope",
                run_id: "run_1",
                new_expires_at: "2026-01-01T02:00:00Z",
                idempotency_key: None,
            })
            .is_err());

        // Not yet expired at 00:30.
        assert!(store
            .expire_leases("i1", "2026-01-01T00:30:00Z")
            .expect("not expired")
            .is_empty());
        // Expired at 02:00: lease/run/effect all transition.
        let expired = store
            .expire_leases("i1", "2026-01-01T02:00:00Z")
            .expect("expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].effect_id, "eff_1");
        let effect_status = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read effect");
        assert_eq!(as_text(&effect_status[0][0]), "queued");
        let run_status = store
            .sql
            .query(
                "SELECT status FROM runs WHERE run_id = ?1",
                &[text("run_1")],
            )
            .expect("read run");
        assert_eq!(as_text(&run_status[0][0]), "lease_expired");
    }

    /// retry_effect requeues a failed/timed-out effect (guarded) and records an event.
    #[test]
    fn do_store_retry_effect_runs_real_sql() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text("eff_1"),
                    text("i1"),
                    text("schema.coerce"),
                    text("failed"),
                    text("{}"),
                ],
            )
            .expect("seed effect");
        let ev = store
            .retry_effect(RetryEffect {
                instance_id: "i1",
                effect_id: "eff_1",
                retry_after: Some("2026-01-01T00:00:00Z"),
                idempotency_key: None,
            })
            .expect("retry");
        assert!(ev.event_id.starts_with("evt_"));
        let status = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read");
        assert_eq!(as_text(&status[0][0]), "queued");
        // A now-queued (not failed/timed_out) effect is not retryable.
        assert!(store
            .retry_effect(RetryEffect {
                instance_id: "i1",
                effect_id: "eff_1",
                retry_after: None,
                idempotency_key: None,
            })
            .is_err());
    }

    /// claimable_effects applies the dependency gate, the cancellation-request
    /// exclusion, and the capability policy block. Real SQL end-to-end.
    #[test]
    fn do_store_claimable_effects_runs_real_sql() {
        let store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
            &[text("prog_1"), text("orders")],
        );
        seed(
            "INSERT INTO program_versions (version_id, program_id, declared_profiles) \
             VALUES (?1, ?2, ?3)",
            &[text("ver_1"), text("prog_1"), text("[]")],
        );
        seed(
            "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
             effective_authority, status, input_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("i1"),
                text("prog_1"),
                text("ver_1"),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );
        // A registered admitted kind: provider + capability + global binding, so
        // an effect of this kind passes the (now real) admission gate. (Since the
        // DO package bootstrap, coordination/file/tracker/signal kinds go through
        // the same gate as native — nothing is waved through but `timer.wait`.)
        seed(
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[text("p_demo"), text("builtin.demo"), text("builtin"), text("builtin.demo"), text("{}")],
        );
        seed(
            "INSERT INTO capability_schemas (capability, description, schema_json) VALUES (?1, ?2, ?3)",
            &[text("builtin.demo"), text(""), text("{}")],
        );
        seed(
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[text("b_demo"), SqlValue::Null, text("builtin.demo"), text("builtin"), text("{}")],
        );

        // A queued effect of the admitted kind is immediately claimable.
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("eff_q"),
                text("i1"),
                text("builtin.demo"),
                text("queued"),
                text("{}"),
                text("2026-01-01T00:00:00Z"),
            ],
        );
        // A provider effect with no registered provider is policy-blocked (filtered out).
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, \
             required_capabilities, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("eff_p"),
                text("i1"),
                text("schema.coerce"),
                text("queued"),
                text("{}"),
                text("[]"),
                text("2026-01-01T00:00:01Z"),
            ],
        );
        // A dependency-blocked effect whose upstream has NOT completed is gated out.
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("eff_up"),
                text("i1"),
                text("builtin.demo"),
                text("queued"),
                text("{}"),
                text("2026-01-01T00:00:02Z"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("eff_down"),
                text("i1"),
                text("builtin.demo"),
                text("blocked_by_dependency"),
                text("{}"),
                text("2026-01-01T00:00:03Z"),
            ],
        );
        seed(
            "INSERT INTO effect_dependencies (instance_id, downstream_effect_id, \
             upstream_effect_id, predicate) VALUES (?1, ?2, ?3, ?4)",
            &[
                text("i1"),
                text("eff_down"),
                text("eff_up"),
                text("succeeds"),
            ],
        );

        let claimable = store.claimable_effects("i1").expect("claimable");
        let ids: Vec<&str> = claimable.iter().map(|e| e.effect_id.as_str()).collect();
        // eff_q and eff_up are claimable; eff_p is policy-blocked; eff_down is gated.
        assert_eq!(ids, vec!["eff_q", "eff_up"]);

        // A non-running instance yields nothing.
        store
            .sql
            .execute(
                "UPDATE instances SET status = 'paused' WHERE instance_id = ?1",
                &[text("i1")],
            )
            .expect("pause");
        assert!(store.claimable_effects("i1").expect("none").is_empty());
    }

    /// start_run claims a queued effect: it records effect.run_started, flips the
    /// effect to running, and creates the run + lease rows. Guards (policy block,
    /// unmet dependency) are enforced. Real SQL.
    #[test]
    fn do_claim_list_persists_policy_block_and_registration_recovers_it() {
        // Parity with the native store: an effect whose profile is
        // unregistered is persisted as blocked_by_profile (with reason and an
        // effect.blocked event) by the claim-list filter, and registering the
        // profile later makes it claimable again.
        let store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
            &[text("prog_1"), text("orders")],
        );
        seed(
            "INSERT INTO program_versions (version_id, program_id, declared_profiles) \
             VALUES (?1, ?2, ?3)",
            &[text("ver_1"), text("prog_1"), text("[]")],
        );
        seed(
            "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
             effective_authority, status, input_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("i1"),
                text("prog_1"),
                text("ver_1"),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("p_tell"),
                text("agent.tell"),
                text("builtin"),
                text("agent.tell"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO capability_schemas (capability, description, schema_json) VALUES (?1, ?2, ?3)",
            &[text("agent.tell"), text(""), text("{}")],
        );
        seed(
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("b_tell"),
                SqlValue::Null,
                text("agent.tell"),
                text("builtin"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, \
             required_capabilities, profile) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("eff_t"),
                text("i1"),
                text("agent.tell"),
                text("queued"),
                text("{}"),
                text("[]"),
                text("ghost"),
            ],
        );

        let claimable = store.claimable_effects("i1").expect("claimable listing");
        assert!(claimable.is_empty(), "blocked effect must not be claimable");
        let row = store
            .sql
            .query(
                "SELECT status, policy_block_reason FROM effects WHERE effect_id = ?1",
                &[text("eff_t")],
            )
            .expect("read effect");
        assert_eq!(as_text(&row[0][0]), "blocked_by_profile");
        assert_eq!(as_text(&row[0][1]), "profile `ghost` is not registered");
        let events = store
            .sql
            .query(
                "SELECT COUNT(*) FROM events WHERE event_type = 'effect.blocked'",
                &[],
            )
            .expect("count events");
        assert_eq!(as_i64(&events[0][0]), 1);

        // Re-observation writes nothing new.
        let claimable = store.claimable_effects("i1").expect("claimable listing");
        assert!(claimable.is_empty());
        let events = store
            .sql
            .query(
                "SELECT COUNT(*) FROM events WHERE event_type = 'effect.blocked'",
                &[],
            )
            .expect("count events");
        assert_eq!(as_i64(&events[0][0]), 1);

        // Registering the profile recovers the effect.
        seed(
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, \
             allowed_capabilities, config_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("profile-ghost"),
                text("ghost"),
                text("late-registered"),
                text("audit"),
                text("[]"),
                text("{}"),
            ],
        );
        let claimable = store.claimable_effects("i1").expect("claimable listing");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "eff_t");
    }

    #[test]
    fn do_store_start_run_runs_real_sql() {
        let mut store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
            &[text("prog_1"), text("orders")],
        );
        seed(
            "INSERT INTO program_versions (version_id, program_id, declared_profiles) \
             VALUES (?1, ?2, ?3)",
            &[text("ver_1"), text("prog_1"), text("[]")],
        );
        seed(
            "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
             effective_authority, status, input_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("i1"),
                text("prog_1"),
                text("ver_1"),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );
        // Register the admitted demo kind (provider + capability + global
        // binding) so it passes the now-real admission gate (see the DO package
        // bootstrap; only `timer.wait` is waved through).
        seed(
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[text("p_demo"), text("builtin.demo"), text("builtin"), text("builtin.demo"), text("{}")],
        );
        seed(
            "INSERT INTO capability_schemas (capability, description, schema_json) VALUES (?1, ?2, ?3)",
            &[text("builtin.demo"), text(""), text("{}")],
        );
        seed(
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[text("b_demo"), SqlValue::Null, text("builtin.demo"), text("builtin"), text("{}")],
        );
        // A queued effect of the admitted kind — claimable.
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_1"),
                text("i1"),
                text("builtin.demo"),
                text("queued"),
                text("{\"a\":1}"),
            ],
        );
        // A provider effect with no registered provider (policy-blocked later).
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json, \
             required_capabilities) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &[
                text("eff_p"),
                text("i1"),
                text("schema.coerce"),
                text("queued"),
                text("{}"),
                text("[]"),
            ],
        );
        // An effect with an unmet dependency (dependency-gated later).
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_up"),
                text("i1"),
                text("builtin.demo"),
                text("queued"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_dn"),
                text("i1"),
                text("builtin.demo"),
                text("queued"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effect_dependencies (instance_id, downstream_effect_id, \
             upstream_effect_id, predicate) VALUES (?1, ?2, ?3, ?4)",
            &[text("i1"), text("eff_dn"), text("eff_up"), text("succeeds")],
        );

        let run = RunStart {
            instance_id: "i1",
            effect_id: "eff_1",
            run_id: "run_1",
            provider: "builtin",
            worker_id: "w1",
            lease_id: "lse_1",
            lease_expires_at: "2026-01-01T01:00:00Z",
            metadata_json: "{}",
        };
        let ev = store.start_run(run).expect("start_run");
        assert!(ev.event_id.starts_with("evt_"));
        // Effect running, run + lease created, fingerprint injected into metadata.
        let eff = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read effect");
        assert_eq!(as_text(&eff[0][0]), "running");
        let runs = store.list_runs("i1").expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].provider, "builtin");
        assert!(runs[0].metadata_json.contains("execution_fingerprint"));
        let leases = store
            .sql
            .query(
                "SELECT status FROM leases WHERE lease_id = ?1",
                &[text("lse_1")],
            )
            .expect("read lease");
        assert_eq!(as_text(&leases[0][0]), "active");

        // The provider effect with no registered provider is policy-blocked.
        let blocked = store.start_run(RunStart {
            instance_id: "i1",
            effect_id: "eff_p",
            run_id: "run_p",
            provider: "x",
            worker_id: "w1",
            lease_id: "lse_p",
            lease_expires_at: "2026-01-01T01:00:00Z",
            metadata_json: "{}",
        });
        assert!(matches!(blocked, Err(StoreError::PolicyBlocked { .. })));

        // The effect with an unmet dependency is conflict-gated.
        assert!(store
            .start_run(RunStart {
                instance_id: "i1",
                effect_id: "eff_dn",
                run_id: "run_dn",
                provider: "builtin",
                worker_id: "w1",
                lease_id: "lse_dn",
                lease_expires_at: "2026-01-01T01:00:00Z",
                metadata_json: "{}",
            })
            .is_err());
    }

    /// complete_effect records the terminal event, transitions run/lease/effect,
    /// satisfies dependents, and is guarded against a double terminal.
    /// complete_effect_with_terminal_diagnostic also records a diagnostic. Real SQL.
    #[test]
    fn do_store_complete_effect_runs_real_sql() {
        use whipplescript_core::Severity;
        let mut store = store();
        // Seed a running effect + run + lease, plus a dependent blocked on it.
        for (sql, params) in [
            (
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![text("eff_1"), text("i1"), text("schema.coerce"), text("running"), text("{}")],
            ),
            (
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![text("eff_dep"), text("i1"), text("schema.coerce"), text("blocked_by_dependency"), text("{}")],
            ),
            (
                "INSERT INTO effect_dependencies (instance_id, downstream_effect_id, \
                 upstream_effect_id, predicate) VALUES (?1, ?2, ?3, ?4)",
                vec![text("i1"), text("eff_dep"), text("eff_1"), text("succeeds")],
            ),
            (
                "INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![text("run_1"), text("i1"), text("eff_1"), text("p"), text("w"), text("running")],
            ),
            (
                "INSERT INTO leases (lease_id, instance_id, run_id, effect_id, status, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                vec![text("lse_1"), text("i1"), text("run_1"), text("eff_1"), text("active"), text("2026-01-01T00:00:00Z")],
            ),
        ] {
            store.sql.execute(sql, &params).expect("seed");
        }

        let completion = EffectCompletion {
            instance_id: "i1",
            effect_id: "eff_1",
            run_id: "run_1",
            provider: "p",
            worker_id: "w",
            status: "completed",
            exit_code: Some(0),
            summary: Some("ok"),
            metadata_json: "{}",
            idempotency_key: Some("done-1"),
        };
        let ev = store.complete_effect(completion).expect("complete");
        assert!(ev.event_id.starts_with("evt_"));
        // run -> completed, lease -> released, effect -> completed.
        let run = store
            .sql
            .query(
                "SELECT status FROM runs WHERE run_id = ?1",
                &[text("run_1")],
            )
            .expect("run");
        assert_eq!(as_text(&run[0][0]), "completed");
        let lease = store
            .sql
            .query(
                "SELECT status FROM leases WHERE lease_id = ?1",
                &[text("lse_1")],
            )
            .expect("lease");
        assert_eq!(as_text(&lease[0][0]), "released");
        // The dependent effect is now queued (dependency satisfied).
        let dep = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_dep")],
            )
            .expect("dep");
        assert_eq!(as_text(&dep[0][0]), "queued");

        // A second completion of the same run is rejected (double terminal).
        let again = store.complete_effect(EffectCompletion {
            instance_id: "i1",
            effect_id: "eff_1",
            run_id: "run_1",
            provider: "p",
            worker_id: "w",
            status: "completed",
            exit_code: Some(0),
            summary: None,
            metadata_json: "{}",
            idempotency_key: Some("done-2"),
        });
        assert!(again.is_err());

        // complete_effect_with_terminal_diagnostic records a diagnostic row.
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text("eff_2"),
                    text("i1"),
                    text("schema.coerce"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed eff_2");
        store
            .sql
            .execute(
                "INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    text("run_2"),
                    text("i1"),
                    text("eff_2"),
                    text("p"),
                    text("w"),
                    text("running"),
                ],
            )
            .expect("seed run_2");
        store
            .complete_effect_with_terminal_diagnostic(
                EffectCompletion {
                    instance_id: "i1",
                    effect_id: "eff_2",
                    run_id: "run_2",
                    provider: "p",
                    worker_id: "w",
                    status: "failed",
                    exit_code: Some(1),
                    summary: Some("boom"),
                    metadata_json: "{}",
                    idempotency_key: Some("fail-1"),
                },
                Some(TerminalDiagnosticRecord {
                    program_id: None,
                    program_version_id: None,
                    severity: Severity::Error,
                    code: Some("E9".to_owned()),
                    message: "kaboom".to_owned(),
                    source_span_json: None,
                    subject_type: None,
                    subject_id: None,
                    assertion_id: None,
                    evidence_ids_json: "[]".to_owned(),
                    artifact_ids_json: "[]".to_owned(),
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: Some("diag-f1".to_owned()),
                }),
            )
            .expect("complete with diagnostic");
        let diags = store.list_diagnostics(Some("i1")).expect("diags");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].effect_id.as_deref(), Some("eff_2"));
    }

    /// commit_rule records the rule.committed event, inserts derived facts, consumes
    /// triggering facts, queues effects + dependency edges, and records rule-commit
    /// evidence. The revision guard rejects a stale expectation. Real SQL.
    #[test]
    fn do_store_commit_rule_runs_real_sql() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");
        // A pre-existing fact the rule will consume.
        store
            .sql
            .execute(
                "INSERT INTO facts (fact_id, instance_id, name, key, value_json, provenance_class) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[text("f_old"), text("i1"), text("trigger"), text("k"), text("1"), text("derived")],
            )
            .expect("seed fact");

        let facts = [NewFact {
            fact_id: "f_new",
            name: "ready",
            key: "k",
            value_json: "true",
            schema_id: None,
            provenance_class: "derived",
            correlation_id: None,
            source_span_json: None,
        }];
        let effects = [NewEffect {
            effect_id: "eff_new",
            kind: "schema.coerce",
            target: None,
            input_json: "{}",
            status: "queued",
            idempotency_key: "eff-idem",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }];
        let consumed = ["f_old"];
        let ev = store
            .commit_rule(RuleCommit {
                instance_id: "i1",
                rule: "r.a",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &consumed,
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-1"),
                marks: &[],
                context_json: None,
            })
            .expect("commit_rule");
        assert!(ev.event_id.starts_with("evt_"));
        // New fact active, old fact consumed, effect queued, evidence recorded.
        let active: Vec<String> = store
            .list_facts("i1")
            .expect("facts")
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(active, vec!["ready".to_string()]);
        let effs = store.list_effects("i1").expect("effects");
        assert_eq!(effs.len(), 1);
        assert_eq!(effs[0].effect_id, "eff_new");
        assert!(!store.list_evidence("i1").expect("evidence").is_empty());

        // The revision guard rejects a mismatched expectation.
        let guarded = store.commit_rule_with_revision_guard(
            RuleCommit {
                instance_id: "i1",
                rule: "r.b",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-2"),
                marks: &[],
                context_json: None,
            },
            RuleCommitRevisionGuard {
                program_version_id: "ver_WRONG",
                revision_epoch: 99,
            },
        );
        assert!(guarded.is_err());
    }

    /// request_effect_cancellation records a request (idempotent) + evidence for a
    /// running effect; cancel_effect terminates it and resolves the request. Real SQL.
    #[test]
    fn do_store_cancellation_runs_real_sql() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text("eff_1"),
                    text("i1"),
                    text("agent.tell"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed effect");
        store
            .sql
            .execute(
                "INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    text("run_1"),
                    text("i1"),
                    text("eff_1"),
                    text("p"),
                    text("w"),
                    text("running"),
                ],
            )
            .expect("seed run");

        let view = store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: "i1",
                effect_id: "eff_1",
                revision_id: None,
                reason: Some("user asked"),
                requested_by: "operator",
                causation_event_id: None,
                idempotency_key: Some("cancel-idem"),
            })
            .expect("request cancel");
        assert!(view.request_id.starts_with("ecr_"));
        assert_eq!(view.status, "requested");
        assert!(store
            .effect_has_open_cancellation_request("i1", "eff_1")
            .expect("open?"));
        // Idempotent replay returns the same request id.
        let view2 = store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: "i1",
                effect_id: "eff_1",
                revision_id: None,
                reason: Some("user asked"),
                requested_by: "operator",
                causation_event_id: None,
                idempotency_key: Some("cancel-idem"),
            })
            .expect("replay");
        assert_eq!(view.request_id, view2.request_id);
        // Evidence + an active_run link were recorded.
        assert!(store
            .list_evidence_links("i1")
            .expect("links")
            .iter()
            .any(|l| l.relation == "active_run" && l.target_id == "run_1"));

        // cancel_effect terminates the effect and resolves the request to terminal.
        store
            .cancel_effect(EffectCancellation {
                instance_id: "i1",
                effect_id: "eff_1",
                reason: Some("done"),
                idempotency_key: Some("term-1"),
            })
            .expect("cancel");
        let eff = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read");
        assert_eq!(as_text(&eff[0][0]), "cancelled");
        assert!(!store
            .effect_has_open_cancellation_request("i1", "eff_1")
            .expect("open?"));
        // A second cancel is rejected (already terminal).
        assert!(store
            .cancel_effect(EffectCancellation {
                instance_id: "i1",
                effect_id: "eff_1",
                reason: None,
                idempotency_key: Some("term-2"),
            })
            .is_err());
    }

    /// revision_cancellation_impact classifies pending vs running effects by policy.
    #[test]
    fn do_store_revision_cancellation_impact_runs_real_sql() {
        let store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
             workflow_principal, effective_authority, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                text("i1"),
                text("p"),
                text("ver_1"),
                int(2),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_q"),
                text("i1"),
                text("schema.coerce"),
                text("queued"),
                text("{}"),
            ],
        );
        seed(
            "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text("eff_r"),
                text("i1"),
                text("schema.coerce"),
                text("running"),
                text("{}"),
            ],
        );

        // keep: nothing cancelled.
        let keep = store
            .revision_cancellation_impact("i1", "keep")
            .expect("keep");
        assert!(keep.terminal_cancel_effects.is_empty());
        assert!(keep.request_cancel_effects.is_empty());
        assert_eq!(keep.active_revision_epoch, 2);

        // cancel_queued: pending effect terminates, running untouched.
        let cq = store
            .revision_cancellation_impact("i1", "cancel_queued")
            .expect("cancel_queued");
        assert_eq!(cq.terminal_cancel_effects, vec!["eff_q".to_string()]);
        assert!(cq.request_cancel_effects.is_empty());

        // request_running: pending terminates + running is request-cancelled.
        let rr = store
            .revision_cancellation_impact("i1", "request_running")
            .expect("request_running");
        assert_eq!(rr.terminal_cancel_effects, vec!["eff_q".to_string()]);
        assert_eq!(rr.request_cancel_effects, vec!["eff_r".to_string()]);

        // Unknown policy rejected.
        assert!(store.revision_cancellation_impact("i1", "bogus").is_err());
    }

    /// analyze_revision_compatibility / analyze_revision_candidate run the structural
    /// diff (root workflow + contracts) and the active-fact schema typecheck.
    #[test]
    fn do_store_analyze_revision_runs_real_sql() {
        let store = store();
        let seed = |sql: &str, params: &[SqlValue]| store.sql.execute(sql, params).expect(sql);
        seed(
            "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
            &[text("prog_1"), text("orders")],
        );
        // Active version: workflow "main", one input contract q:int.
        let active_summary = r#"{"workflow":"main","workflow_contracts":[
            {"kind":"input","name":"q","type":"int"}],"schemas":[]}"#;
        seed(
            "INSERT INTO program_versions (version_id, program_id, source_hash, analysis_summary) \
             VALUES (?1, ?2, ?3, ?4)",
            &[
                text("ver_active"),
                text("prog_1"),
                text("sh_active"),
                text(active_summary),
            ],
        );
        // Compatible candidate: identical summary.
        seed(
            "INSERT INTO program_versions (version_id, program_id, source_hash, analysis_summary) \
             VALUES (?1, ?2, ?3, ?4)",
            &[
                text("ver_ok"),
                text("prog_1"),
                text("sh_ok"),
                text(active_summary),
            ],
        );
        // Incompatible candidate: root workflow renamed + contract type changed.
        let bad_summary = r#"{"workflow":"other","workflow_contracts":[
            {"kind":"input","name":"q","type":"string"}],"schemas":[]}"#;
        seed(
            "INSERT INTO program_versions (version_id, program_id, source_hash, analysis_summary) \
             VALUES (?1, ?2, ?3, ?4)",
            &[
                text("ver_bad"),
                text("prog_1"),
                text("sh_bad"),
                text(bad_summary),
            ],
        );
        seed(
            "INSERT INTO instances (instance_id, program_id, version_id, workflow_principal, \
             effective_authority, status, input_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                text("i1"),
                text("prog_1"),
                text("ver_active"),
                text("root"),
                text("{}"),
                text("running"),
                text("{}"),
            ],
        );

        let ok = store
            .analyze_revision_compatibility("i1", "ver_ok")
            .expect("ok");
        assert!(ok.compatible, "identical summary is compatible");

        let bad = store
            .analyze_revision_compatibility("i1", "ver_bad")
            .expect("bad");
        assert!(!bad.compatible);
        let codes: Vec<&str> = bad.diagnostics.iter().map(|d| d.code.as_str()).collect();
        assert!(codes.contains(&"revision.root_workflow_changed"));
        assert!(codes.contains(&"revision.contract_changed"));

        // analyze_revision_candidate against an inline summary flags the mismatch.
        let cand = store
            .analyze_revision_candidate(
                "i1",
                RevisionCandidate {
                    candidate_version_id: "ver_x",
                    program_name: "orders",
                    analysis_summary_json: bad_summary,
                },
            )
            .expect("candidate");
        assert!(!cand.compatible);
    }

    /// activate_revision bumps the epoch, records the revision + event, cancels
    /// queued effects per policy, and is idempotent on its key. Real SQL.
    #[test]
    fn do_store_activate_revision_runs_real_sql() {
        let mut store = store();
        let summary = r#"{"workflow":"main","workflow_contracts":[],"schemas":[]}"#;
        for (sql, params) in [
            (
                "INSERT INTO programs (program_id, name) VALUES (?1, ?2)",
                vec![text("prog_1"), text("orders")],
            ),
            (
                "INSERT INTO program_versions (version_id, program_id, source_hash, analysis_summary) \
                 VALUES (?1, ?2, ?3, ?4)",
                vec![text("ver_a"), text("prog_1"), text("sh_a"), text(summary)],
            ),
            (
                "INSERT INTO program_versions (version_id, program_id, source_hash, analysis_summary) \
                 VALUES (?1, ?2, ?3, ?4)",
                vec![text("ver_b"), text("prog_1"), text("sh_b"), text(summary)],
            ),
            (
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vec![text("i1"), text("prog_1"), text("ver_a"), int(0), text("root"), text("{}"), text("running"), text("{}")],
            ),
            (
                "INSERT INTO effects (effect_id, instance_id, kind, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                vec![text("eff_q"), text("i1"), text("schema.coerce"), text("queued"), text("{}")],
            ),
        ] {
            store.sql.execute(sql, &params).expect("seed");
        }

        let activation = RevisionActivation {
            instance_id: "i1",
            from_version_id: "ver_a",
            to_version_id: "ver_b",
            activation_policy_json: "{}",
            cancellation_policy: "cancel_queued",
            idempotency_key: Some("act-1"),
        };
        let view = store.activate_revision(activation).expect("activate");
        assert!(view.revision_id.starts_with("rev_"));
        assert_eq!(view.epoch, 1);
        assert_eq!(view.to_version_id, "ver_b");
        // Instance advanced to ver_b epoch 1; the queued effect was cancelled.
        let inst = store.get_instance("i1").expect("get").expect("some");
        assert_eq!(inst.version_id, "ver_b");
        assert_eq!(inst.revision_epoch, 1);
        let eff = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_q")],
            )
            .expect("read");
        assert_eq!(as_text(&eff[0][0]), "cancelled");
        assert_eq!(store.list_instance_revisions("i1").expect("revs").len(), 1);

        // Idempotent replay returns the same revision without a second row.
        let view2 = store
            .activate_revision(RevisionActivation {
                instance_id: "i1",
                from_version_id: "ver_a",
                to_version_id: "ver_b",
                activation_policy_json: "{}",
                cancellation_policy: "cancel_queued",
                idempotency_key: Some("act-1"),
            })
            .expect("replay");
        assert_eq!(view.revision_id, view2.revision_id);
        assert_eq!(store.list_instance_revisions("i1").expect("revs").len(), 1);

        // A stale from_version is rejected (already advanced to ver_b).
        assert!(store
            .activate_revision(RevisionActivation {
                instance_id: "i1",
                from_version_id: "ver_a",
                to_version_id: "ver_b",
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("act-2"),
            })
            .is_err());
    }

    /// rebuild_projections deletes the projection tables and reconstructs them by
    /// replaying the event log: a corrupted fact/effect is restored, and a
    /// run-started + terminal pair rebuilds the run in its completed state.
    #[test]
    fn do_store_rebuild_projections_runs_real_sql() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        // commit_rule records a rule.committed event + inserts a fact and an effect.
        let facts = [NewFact {
            fact_id: "f1",
            name: "ready",
            key: "k",
            value_json: "true",
            schema_id: None,
            provenance_class: "derived",
            correlation_id: None,
            source_span_json: None,
        }];
        let effects = [NewEffect {
            effect_id: "eff_1",
            kind: "tracker.push",
            target: None,
            input_json: "{}",
            status: "queued",
            idempotency_key: "e1",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "i1",
                rule: "r.a",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("c1"),
                marks: &[],
                context_json: None,
            })
            .expect("commit");
        // Then start + complete a run for the effect (appends run_started + terminal).
        store
            .start_run(RunStart {
                instance_id: "i1",
                effect_id: "eff_1",
                run_id: "run_1",
                provider: "builtin",
                worker_id: "w1",
                lease_id: "lse_1",
                lease_expires_at: "2026-01-01T01:00:00Z",
                metadata_json: "{}",
            })
            .expect("start");
        store
            .complete_effect(EffectCompletion {
                instance_id: "i1",
                effect_id: "eff_1",
                run_id: "run_1",
                provider: "builtin",
                worker_id: "w1",
                status: "completed",
                exit_code: Some(0),
                summary: None,
                metadata_json: "{}",
                idempotency_key: Some("done"),
            })
            .expect("complete");

        // Corrupt the projections: wipe the fact and flip the effect status.
        store
            .sql
            .execute("DELETE FROM facts WHERE instance_id = ?1", &[text("i1")])
            .expect("wipe facts");
        store
            .sql
            .execute(
                "UPDATE effects SET status = 'queued' WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("corrupt effect");

        // Rebuild from the event log.
        store.rebuild_projections("i1").expect("rebuild");

        // The fact is reconstructed, the effect is back to completed, and the run
        // was rebuilt in its completed state with the lease released.
        let facts = store.list_facts("i1").expect("facts");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].name, "ready");
        let eff = store
            .sql
            .query(
                "SELECT status FROM effects WHERE effect_id = ?1",
                &[text("eff_1")],
            )
            .expect("read effect");
        assert_eq!(as_text(&eff[0][0]), "completed");
        let runs = store.list_runs("i1").expect("runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "completed");
    }

    /// RC-2 Delta A (DO mirror): rebuild_projections_to reflects instance state
    /// AS OF event N — an effect committed after N is absent; one at/before N is
    /// present. Unbounded rebuild restores the full current state.
    #[test]
    fn do_store_rebuild_projections_to_bounded_by_sequence() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        let effect_exists =
            |store: &DoSqliteStore<super::test_support::RusqliteDoSql>, effect_id: &str| -> bool {
                !store
                    .sql
                    .query(
                        "SELECT 1 FROM effects WHERE effect_id = ?1",
                        &[text(effect_id)],
                    )
                    .expect("effect count")
                    .is_empty()
            };
        let max_sequence = |store: &DoSqliteStore<super::test_support::RusqliteDoSql>| -> i64 {
            let rows = store
                .sql
                .query(
                    "SELECT MAX(sequence) FROM events WHERE instance_id = ?1",
                    &[text("i1")],
                )
                .expect("max sequence");
            match &rows[0][0] {
                SqlValue::Int(n) => *n,
                other => panic!("expected integer sequence, got {other:?}"),
            }
        };

        let effect_a = [NewEffect {
            effect_id: "eff_a",
            kind: "tracker.push",
            target: None,
            input_json: "{}",
            status: "queued",
            idempotency_key: "e_a",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "i1",
                rule: "r.a",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effect_a,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("c_a"),
                marks: &[],
                context_json: None,
            })
            .expect("commit A");
        let cut = max_sequence(&store);

        let effect_b = [NewEffect {
            effect_id: "eff_b",
            kind: "tracker.push",
            target: None,
            input_json: "{}",
            status: "queued",
            idempotency_key: "e_b",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "i1",
                rule: "r.b",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effect_b,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("c_b"),
                marks: &[],
                context_json: None,
            })
            .expect("commit B");

        // Cut AT effect A's commit sequence: A is in, B (later) is out.
        store
            .rebuild_projections_to("i1", cut)
            .expect("bounded rebuild");
        assert!(effect_exists(&store, "eff_a"), "effect A (<= N) present");
        assert!(!effect_exists(&store, "eff_b"), "effect B (> N) absent");

        // Unbounded rebuild restores both.
        store.rebuild_projections("i1").expect("full rebuild");
        assert!(effect_exists(&store, "eff_a"), "effect A present in full");
        assert!(effect_exists(&store, "eff_b"), "effect B present in full");
    }

    /// RC-3 DO mirror: capture_checkpoint folds the file manifest from
    /// file.write.completed facts (latest-write-wins), stores it
    /// content-addressed (INV-4), records the context.checkpoint cut carrier,
    /// and refuses while an effect is running (INV-2 no-in-flight straddle).
    #[test]
    fn do_store_capture_checkpoint_folds_manifest_and_guards_quiescence() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        // Insert file.write.completed fact.derived events in the RC-1 payload
        // shape (write descriptor nested at value.value); a.txt is overwritten.
        let write_event = |store: &DoSqliteStore<super::test_support::RusqliteDoSql>,
                           seq: i64,
                           key: &str,
                           path: &str,
                           content_hash: &str| {
            let payload = serde_json::json!({
                "name": "file.write.completed",
                "key": key,
                "value": {
                    "effect_id": key,
                    "value": { "store": "workspace", "path": path, "content_hash": content_hash },
                },
            })
            .to_string();
            store
                .sql
                .execute(
                    "INSERT INTO events (event_id, instance_id, sequence, event_type, \
                     payload_json, occurred_at, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    &[
                        text(&format!("evt_{key}")),
                        text("i1"),
                        int(seq),
                        text("fact.derived"),
                        text(&payload),
                        text("2030-01-01T00:00:00Z"),
                        text("kernel"),
                    ],
                )
                .expect("insert fact.derived event");
        };
        write_event(&store, 1, "w-a1", "a.txt", "hash-a1");
        write_event(&store, 2, "w-b1", "b.txt", "hash-b1");
        write_event(&store, 3, "w-a2", "a.txt", "hash-a2");

        let checkpoint = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: "i1",
                cut_id: "cut-1",
                transcript_ref: Some("step-7"),
                idempotency_key: Some("checkpoint-cut-1"),
            })
            .expect("checkpoint captures at quiescence");
        assert_eq!(checkpoint.file_count, 2);
        assert!(checkpoint.sequence > 3, "checkpoint is the latest sequence");

        let manifest_body = store
            .get_content(&checkpoint.manifest_hash)
            .expect("manifest read")
            .expect("manifest present");
        let manifest: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&manifest_body).expect("manifest parses");
        assert_eq!(manifest.get("a.txt").map(String::as_str), Some("hash-a2"));
        assert_eq!(manifest.get("b.txt").map(String::as_str), Some("hash-b1"));

        let carrier = store
            .sql
            .query(
                "SELECT event_type FROM events WHERE instance_id = ?1 AND sequence = ?2",
                &[text("i1"), int(checkpoint.sequence)],
            )
            .expect("carrier row");
        assert_eq!(as_text(&carrier[0][0]), "context.checkpoint");

        // INV-2: with an effect running, a further capture refuses.
        store
            .sql
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    text("eff_run"),
                    text("i1"),
                    text("agent.tell"),
                    text("running"),
                ],
            )
            .expect("seed running effect");
        let refused = store.capture_checkpoint(CheckpointCapture {
            instance_id: "i1",
            cut_id: "cut-busy",
            transcript_ref: None,
            idempotency_key: None,
        });
        assert!(
            matches!(refused, Err(StoreError::Conflict(_))),
            "checkpoint refuses while an effect runs, got {refused:?}"
        );
    }

    /// RC-4c DO mirror: plan_restore returns the full reconcile (writes + removes)
    /// and commit_restore's marker rewinds the file plane so a later checkpoint
    /// hashes to the cut; refuses on unknown cut / dangling manifest.
    #[test]
    fn do_store_plan_restore_reconciles_and_commit_restore_rewinds() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        // Record a mediated file write: capture the blob content-addressed and
        // append the matching file.write.completed fact.derived event.
        fn record_file_write(
            store: &mut DoSqliteStore<super::test_support::RusqliteDoSql>,
            key: &str,
            path: &str,
            body: &str,
        ) {
            let content_hash = store.put_content(body).expect("blob captures");
            let payload = serde_json::json!({
                "name": "file.write.completed",
                "key": key,
                "value": {
                    "effect_id": key,
                    "value": { "store": "workspace", "path": path, "content_hash": content_hash },
                },
            })
            .to_string();
            store
                .append_event(NewEvent {
                    instance_id: "i1",
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: Some(key),
                })
                .expect("fact.derived appends");
        }

        record_file_write(&mut store, "w-a1", "a.txt", "A1");
        record_file_write(&mut store, "w-b1", "b.txt", "B1");
        let cut = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: "i1",
                cut_id: "cut-1",
                transcript_ref: Some("step-3"),
                idempotency_key: Some("checkpoint-cut-1"),
            })
            .expect("checkpoint captures");
        record_file_write(&mut store, "w-a2", "a.txt", "A2");
        record_file_write(&mut store, "w-c1", "c.txt", "C1");

        let plan = match store.plan_restore("i1", "cut-1").expect("plan resolves") {
            RestoreDecision::Ready(plan) => plan,
            RestoreDecision::Refused { reason } => panic!("unexpected refusal: {reason}"),
        };
        assert_eq!(plan.restored_to_sequence, cut.sequence);
        assert_eq!(plan.writes.get("a.txt").map(String::as_str), Some("A1"));
        assert_eq!(plan.writes.get("b.txt").map(String::as_str), Some("B1"));
        assert_eq!(plan.removes, vec!["c.txt".to_owned()]);

        store
            .commit_restore("i1", plan.restored_to_sequence, "cut-1", Some("restore-1"))
            .expect("restore commits");
        let after = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: "i1",
                cut_id: "cut-after",
                transcript_ref: None,
                idempotency_key: Some("checkpoint-after"),
            })
            .expect("post-restore checkpoint");
        assert_eq!(
            after.manifest_hash, cut.manifest_hash,
            "the file plane rewound to the cut"
        );

        assert!(
            matches!(
                store.plan_restore("i1", "nope").expect("plan resolves"),
                RestoreDecision::Refused { .. }
            ),
            "unknown cut refuses"
        );
    }

    /// RC-4b DO mirror: an unbounded rebuild folds `context.restored` markers —
    /// an effect committed after the cut but before the marker is abandoned;
    /// post-restore work survives (models/maude/restore-replay.maude).
    #[test]
    fn do_store_rebuild_projections_honors_restore_marker() {
        let mut store = store();
        store
            .sql
            .execute(
                "INSERT INTO instances (instance_id, program_id, version_id, revision_epoch, \
                 workflow_principal, effective_authority, status, input_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    text("i1"),
                    text("p"),
                    text("ver_1"),
                    int(0),
                    text("root"),
                    text("{}"),
                    text("running"),
                    text("{}"),
                ],
            )
            .expect("seed instance");

        let effect_exists =
            |store: &DoSqliteStore<super::test_support::RusqliteDoSql>, effect_id: &str| -> bool {
                !store
                    .sql
                    .query(
                        "SELECT 1 FROM effects WHERE effect_id = ?1",
                        &[text(effect_id)],
                    )
                    .expect("effect count")
                    .is_empty()
            };
        let max_sequence = |store: &DoSqliteStore<super::test_support::RusqliteDoSql>| -> i64 {
            match &store
                .sql
                .query(
                    "SELECT MAX(sequence) FROM events WHERE instance_id = ?1",
                    &[text("i1")],
                )
                .expect("max sequence")[0][0]
            {
                SqlValue::Int(n) => *n,
                other => panic!("expected integer sequence, got {other:?}"),
            }
        };
        let commit = |store: &mut DoSqliteStore<super::test_support::RusqliteDoSql>,
                      rule: &str,
                      effect_id: &str,
                      key: &str| {
            let effects = [NewEffect {
                effect_id,
                kind: "tracker.push",
                target: None,
                input_json: "{}",
                status: "queued",
                idempotency_key: key,
                required_capabilities_json: "[]",
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }];
            store
                .commit_rule(RuleCommit {
                    instance_id: "i1",
                    rule,
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: &[],
                    effects: &effects,
                    dependencies: &[],
                    terminal: None,
                    idempotency_key: Some(key),
                    marks: &[],
                    context_json: None,
                })
                .expect("commit");
        };

        commit(&mut store, "r.a", "eff_a", "c_a");
        let cut = max_sequence(&store);
        commit(&mut store, "r.b", "eff_b", "c_b");

        let marker_payload = serde_json::json!({ "restored_to_sequence": cut }).to_string();
        store
            .append_event(NewEvent {
                instance_id: "i1",
                event_type: "context.restored",
                payload_json: &marker_payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("restore-marker-1"),
            })
            .expect("marker appends");
        commit(&mut store, "r.c", "eff_c", "c_c");

        store
            .rebuild_projections("i1")
            .expect("marker-aware rebuild");
        assert!(effect_exists(&store, "eff_a"), "A survives the restore");
        assert!(!effect_exists(&store, "eff_b"), "B abandoned by the marker");
        assert!(
            effect_exists(&store, "eff_c"),
            "C (post-restore) stays live"
        );
    }
}
