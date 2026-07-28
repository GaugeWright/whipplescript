//! The experimentation/improve evidence store: the workspace-scoped ledger
//! behind `gauge` ambient scoring, pinned scenarios, and `whip improve`
//! campaign records (`spec/experimentation-subsystem-research-note.md` §8,
//! `spec/improve-design-note.md` §10).
//!
//! State model, mirroring the builtin tracker's cure: raw observations and
//! campaign records are APPEND-ONLY — an evidence row is never updated, a
//! campaign record is an event log folded on read (`fold_campaign`). Store
//! facts, derive everything: posteriors/estimates are computed by readers,
//! never stored.
//!
//! The two invariant models under `models/maude/` this storage serves:
//! `improve-acceptance.maude` (never surface a dominated candidate) and
//! `improve-holdout.maude` (sealed scenarios never reach the proposer; wear
//! is CUMULATIVE across campaigns, which is why `scenario_wear` lives here
//! rather than inside any one campaign's record).
//!
//! Lives in a workspace-scoped SQLite file (default
//! `.whipplescript/improve.sqlite`), separate from run stores for the same
//! reason the backlog is: run stores are disposable per experiment, the
//! evidence asset is durable — it is the whole point that it accumulates.

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

#[cfg(feature = "native")]
use crate::StoreError;
use crate::StoreResult;

/// Execution-mode provenance column (research note §8/§9.6): `live` = an
/// ambient run the user was doing anyway; `regen` = a campaign or suppose
/// regeneration. Never keys pooling directly; surfaces as the N
/// decomposition (`N=64 (7 regen · 57 live)`).
pub const EXECUTION_MODES: &[&str] = &["live", "regen"];

/// One appended gauge observation. Scores are instrument readings: `score`
/// is the reading on the gauge's own scale, `passed` is the bar verdict when
/// the gauge declares a bar (None when it declares none).
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceRow {
    pub evidence_id: i64,
    pub gauge: String,
    pub score: f64,
    pub passed: Option<bool>,
    pub instance_id: Option<String>,
    pub program_hash: Option<String>,
    pub branch_ref: Option<String>,
    pub execution_mode: String,
    pub scorer: String,
    pub scenario: Option<String>,
    pub campaign_id: Option<String>,
    pub candidate_id: Option<String>,
    pub cost_micros: i64,
    pub tags: Vec<String>,
    pub created_at: String,
}

/// One `evidence_summary` aggregate row (per gauge).
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceSummaryRow {
    pub gauge: String,
    pub n: i64,
    pub live: i64,
    pub regen: i64,
    pub score_sum: f64,
    pub passes: i64,
}

/// Input for one appended observation.
#[derive(Clone, Debug, Default)]
pub struct NewEvidence<'a> {
    pub gauge: &'a str,
    pub score: f64,
    pub passed: Option<bool>,
    pub instance_id: Option<&'a str>,
    pub program_hash: Option<&'a str>,
    pub branch_ref: Option<&'a str>,
    pub execution_mode: &'a str,
    pub scorer: &'a str,
    pub scenario: Option<&'a str>,
    pub campaign_id: Option<&'a str>,
    pub candidate_id: Option<&'a str>,
    pub cost_micros: i64,
    pub tags: Vec<String>,
}

/// A pinned scenario: a named run kept because it exemplifies something.
/// v1 identity is the run's frozen input (regeneration = re-run the
/// workflow on it); mark-level prefix cuts arrive with the checkpoint
/// substrate and widen this record, they do not replace it.
#[derive(Clone, Debug, PartialEq)]
pub struct ScenarioRow {
    pub name: String,
    pub instance_id: String,
    pub workflow: Option<String>,
    pub input_json: String,
    pub program_hash: Option<String>,
    /// Mark-pinned scenarios: the named cut point and its event-sequence
    /// coordinate in the source instance's log, plus the source store the
    /// prefix replays from. All None = a whole-run (input-replay) pin.
    pub mark: Option<String>,
    pub cut_sequence: Option<i64>,
    pub store_path: Option<String>,
    pub pinned_at: String,
    pub retired: bool,
    /// Cumulative promotion-gate exposure across ALL campaigns.
    pub wear: i64,
}

/// One campaign-record event: append-only, folded on read.
#[derive(Clone, Debug, PartialEq)]
pub struct CampaignEventRow {
    pub campaign_id: String,
    pub seq: i64,
    pub event_type: String,
    pub payload: Value,
    pub created_at: String,
}

/// Folded campaign head-line state for listings; the full record is the
/// event log itself.
#[derive(Clone, Debug, PartialEq)]
pub struct CampaignSummary {
    pub campaign_id: String,
    pub status: String,
    pub spec: Value,
    pub opened_at: String,
    pub last_event_at: String,
    pub candidates: i64,
    pub proposed: i64,
    pub spent_micros: i64,
}

#[cfg(feature = "native")]
pub struct ImproveStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl ImproveStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path).map_err(StoreError::from)?;
        Self::bootstrap(connection)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(StoreError::from)?;
        Self::bootstrap(connection)
    }

    fn bootstrap(connection: Connection) -> StoreResult<Self> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE IF NOT EXISTS evidence_rows (
                   evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   gauge TEXT NOT NULL,
                   score REAL NOT NULL,
                   passed INTEGER,
                   instance_id TEXT,
                   program_hash TEXT,
                   branch_ref TEXT,
                   execution_mode TEXT NOT NULL,
                   scorer TEXT NOT NULL,
                   scenario TEXT,
                   campaign_id TEXT,
                   candidate_id TEXT,
                   cost_micros INTEGER NOT NULL DEFAULT 0,
                   tags_json TEXT NOT NULL DEFAULT '[]',
                   created_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 CREATE INDEX IF NOT EXISTS idx_evidence_gauge
                   ON evidence_rows(gauge, program_hash);
                 CREATE INDEX IF NOT EXISTS idx_evidence_campaign
                   ON evidence_rows(campaign_id, candidate_id);
                 CREATE TABLE IF NOT EXISTS scenarios (
                   name TEXT PRIMARY KEY,
                   instance_id TEXT NOT NULL,
                   workflow TEXT,
                   input_json TEXT NOT NULL,
                   program_hash TEXT,
                   mark TEXT,
                   cut_sequence INTEGER,
                   store_path TEXT,
                   pinned_at TEXT NOT NULL DEFAULT (datetime('now')),
                   retired INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS scenario_wear (
                   scenario TEXT PRIMARY KEY,
                   wear INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS campaign_counter (
                   singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                   next_id INTEGER NOT NULL
                 );
                 INSERT OR IGNORE INTO campaign_counter (singleton, next_id)
                   VALUES (1, 1);
                 CREATE TABLE IF NOT EXISTS campaign_events (
                   campaign_id TEXT NOT NULL,
                   seq INTEGER NOT NULL,
                   event_type TEXT NOT NULL,
                   payload_json TEXT NOT NULL,
                   created_at TEXT NOT NULL DEFAULT (datetime('now')),
                   PRIMARY KEY (campaign_id, seq)
                 );",
            )
            .map_err(StoreError::from)?;
        // Idempotent widening for stores created before mark-pinned
        // scenarios (the ensure-* pattern): ALTER fails harmlessly when the
        // column already exists.
        for alter in [
            "ALTER TABLE scenarios ADD COLUMN mark TEXT",
            "ALTER TABLE scenarios ADD COLUMN cut_sequence INTEGER",
            "ALTER TABLE scenarios ADD COLUMN store_path TEXT",
        ] {
            let _ = connection.execute(alter, []);
        }
        Ok(Self { connection })
    }

    // ------------------------------------------------------------------
    // Evidence ledger
    // ------------------------------------------------------------------

    pub fn record_evidence(&mut self, evidence: NewEvidence<'_>) -> StoreResult<i64> {
        if !EXECUTION_MODES.contains(&evidence.execution_mode) {
            return Err(StoreError::Conflict(format!(
                "unknown execution mode `{}` (expected one of {})",
                evidence.execution_mode,
                EXECUTION_MODES.join(", ")
            )));
        }
        let tags_json = serde_json::to_string(&evidence.tags)
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO evidence_rows (gauge, score, passed, instance_id, program_hash,
                   branch_ref, execution_mode, scorer, scenario, campaign_id, candidate_id,
                   cost_micros, tags_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    evidence.gauge,
                    evidence.score,
                    evidence.passed.map(i64::from),
                    evidence.instance_id,
                    evidence.program_hash,
                    evidence.branch_ref,
                    evidence.execution_mode,
                    evidence.scorer,
                    evidence.scenario,
                    evidence.campaign_id,
                    evidence.candidate_id,
                    evidence.cost_micros,
                    tags_json,
                ],
            )
            .map_err(StoreError::from)?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Raw rows, newest last. Every filter is optional; readers fold.
    pub fn list_evidence(
        &self,
        gauge: Option<&str>,
        campaign_id: Option<&str>,
        candidate_id: Option<&str>,
        program_hash: Option<&str>,
    ) -> StoreResult<Vec<EvidenceRow>> {
        let mut sql = String::from(
            "SELECT evidence_id, gauge, score, passed, instance_id, program_hash, branch_ref,
               execution_mode, scorer, scenario, campaign_id, candidate_id, cost_micros,
               tags_json, created_at
             FROM evidence_rows WHERE 1=1",
        );
        let mut binds: Vec<&str> = Vec::new();
        if let Some(g) = gauge {
            sql.push_str(" AND gauge = ?");
            binds.push(g);
        }
        if let Some(c) = campaign_id {
            sql.push_str(" AND campaign_id = ?");
            binds.push(c);
        }
        if let Some(k) = candidate_id {
            sql.push_str(" AND candidate_id = ?");
            binds.push(k);
        }
        if let Some(p) = program_hash {
            sql.push_str(" AND program_hash = ?");
            binds.push(p);
        }
        sql.push_str(" ORDER BY evidence_id ASC");
        let mut statement = self.connection.prepare(&sql).map_err(StoreError::from)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(binds), |row| {
                let tags_json: String = row.get(13)?;
                Ok(EvidenceRow {
                    evidence_id: row.get(0)?,
                    gauge: row.get(1)?,
                    score: row.get(2)?,
                    passed: row.get::<_, Option<i64>>(3)?.map(|v| v != 0),
                    instance_id: row.get(4)?,
                    program_hash: row.get(5)?,
                    branch_ref: row.get(6)?,
                    execution_mode: row.get(7)?,
                    scorer: row.get(8)?,
                    scenario: row.get(9)?,
                    campaign_id: row.get(10)?,
                    candidate_id: row.get(11)?,
                    cost_micros: row.get(12)?,
                    tags: serde_json::from_str(&tags_json).unwrap_or_default(),
                    created_at: row.get(14)?,
                })
            })
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    /// Per-gauge aggregate over the whole ledger, computed in SQL so the
    /// listing stays O(gauges) as the append-only ledger grows.
    pub fn evidence_summary(&self, gauge: Option<&str>) -> StoreResult<Vec<EvidenceSummaryRow>> {
        let mut sql = String::from(
            "SELECT gauge, COUNT(*),
               SUM(CASE WHEN execution_mode = 'live' THEN 1 ELSE 0 END),
               SUM(CASE WHEN execution_mode = 'regen' THEN 1 ELSE 0 END),
               SUM(score),
               SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END)
             FROM evidence_rows",
        );
        let mut binds: Vec<&str> = Vec::new();
        if let Some(g) = gauge {
            sql.push_str(" WHERE gauge = ?");
            binds.push(g);
        }
        sql.push_str(" GROUP BY gauge ORDER BY gauge");
        let mut statement = self.connection.prepare(&sql).map_err(StoreError::from)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(binds), |row| {
                Ok(EvidenceSummaryRow {
                    gauge: row.get(0)?,
                    n: row.get(1)?,
                    live: row.get(2)?,
                    regen: row.get(3)?,
                    score_sum: row.get::<_, Option<f64>>(4)?.unwrap_or(0.0),
                    passes: row.get(5)?,
                })
            })
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    /// Distinct gauge names present in the ledger.
    pub fn evidence_gauges(&self) -> StoreResult<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT gauge FROM evidence_rows ORDER BY gauge")
            .map_err(StoreError::from)?;
        let rows = statement
            .query_map([], |row| row.get(0))
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    // ------------------------------------------------------------------
    // Scenarios (the pinned regression corpus)
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn pin_scenario(
        &mut self,
        name: &str,
        instance_id: &str,
        workflow: Option<&str>,
        input_json: &str,
        program_hash: Option<&str>,
        mark: Option<&str>,
        cut_sequence: Option<i64>,
        store_path: Option<&str>,
    ) -> StoreResult<()> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO scenarios (name, instance_id, workflow, input_json,
                   program_hash, mark, cut_sequence, store_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    name,
                    instance_id,
                    workflow,
                    input_json,
                    program_hash,
                    mark,
                    cut_sequence,
                    store_path
                ],
            )
            .map_err(StoreError::from)?;
        if inserted == 0 {
            return Err(StoreError::Conflict(format!(
                "scenario `{name}` already pinned"
            )));
        }
        Ok(())
    }

    pub fn get_scenario(&self, name: &str) -> StoreResult<Option<ScenarioRow>> {
        self.connection
            .query_row(
                "SELECT s.name, s.instance_id, s.workflow, s.input_json, s.program_hash,
                   s.mark, s.cut_sequence, s.store_path,
                   s.pinned_at, s.retired, COALESCE(w.wear, 0)
                 FROM scenarios s LEFT JOIN scenario_wear w ON w.scenario = s.name
                 WHERE s.name = ?1",
                params![name],
                scenario_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// All scenarios, retired ones included (readers filter; retirement is
    /// from holdout duty, not from the regression corpus).
    pub fn list_scenarios(&self) -> StoreResult<Vec<ScenarioRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT s.name, s.instance_id, s.workflow, s.input_json, s.program_hash,
                   s.mark, s.cut_sequence, s.store_path,
                   s.pinned_at, s.retired, COALESCE(w.wear, 0)
                 FROM scenarios s LEFT JOIN scenario_wear w ON w.scenario = s.name
                 ORDER BY s.pinned_at, s.name",
            )
            .map_err(StoreError::from)?;
        let rows = statement
            .query_map([], scenario_from_row)
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    /// One promotion-gate exposure: bump the scenario's CUMULATIVE wear
    /// counter and return the new value. At `wear_out_at` the scenario
    /// retires from holdout duty (`improve-holdout.maude` wear-out rule);
    /// retirement here means future campaigns stop sealing it.
    pub fn bump_scenario_wear(&mut self, scenario: &str, wear_out_at: i64) -> StoreResult<i64> {
        self.connection
            .execute(
                "INSERT INTO scenario_wear (scenario, wear) VALUES (?1, 1)
                 ON CONFLICT(scenario) DO UPDATE SET wear = wear + 1",
                params![scenario],
            )
            .map_err(StoreError::from)?;
        let wear: i64 = self
            .connection
            .query_row(
                "SELECT wear FROM scenario_wear WHERE scenario = ?1",
                params![scenario],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        if wear >= wear_out_at {
            self.connection
                .execute(
                    "UPDATE scenarios SET retired = 1 WHERE name = ?1",
                    params![scenario],
                )
                .map_err(StoreError::from)?;
        }
        Ok(wear)
    }

    /// Anchor elicitation against a sealed scenario retires it immediately:
    /// the label is worth more than the seal, counted as a wear-out event.
    pub fn retire_scenario(&mut self, scenario: &str) -> StoreResult<()> {
        self.connection
            .execute(
                "UPDATE scenarios SET retired = 1 WHERE name = ?1",
                params![scenario],
            )
            .map_err(StoreError::from)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Campaign records (append-only, folded on read)
    // ------------------------------------------------------------------

    /// Mint a campaign id and append its opening event carrying the spec.
    pub fn open_campaign(&mut self, spec: &Value) -> StoreResult<String> {
        let next: i64 = self
            .connection
            .query_row(
                "UPDATE campaign_counter SET next_id = next_id + 1 WHERE singleton = 1
                 RETURNING next_id - 1",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        let campaign_id = format!("C-{next}");
        self.append_campaign_event(&campaign_id, "campaign.opened", spec)?;
        Ok(campaign_id)
    }

    pub fn append_campaign_event(
        &mut self,
        campaign_id: &str,
        event_type: &str,
        payload: &Value,
    ) -> StoreResult<i64> {
        let payload_json =
            serde_json::to_string(payload).map_err(|e| StoreError::Conflict(e.to_string()))?;
        let seq: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM campaign_events WHERE campaign_id = ?1",
                params![campaign_id],
                |row| row.get(0),
            )
            .map_err(StoreError::from)?;
        self.connection
            .execute(
                "INSERT INTO campaign_events (campaign_id, seq, event_type, payload_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![campaign_id, seq, event_type, payload_json],
            )
            .map_err(StoreError::from)?;
        Ok(seq)
    }

    pub fn list_campaign_events(&self, campaign_id: &str) -> StoreResult<Vec<CampaignEventRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT campaign_id, seq, event_type, payload_json, created_at
                 FROM campaign_events WHERE campaign_id = ?1 ORDER BY seq",
            )
            .map_err(StoreError::from)?;
        let rows = statement
            .query_map(params![campaign_id], campaign_event_from_row)
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    /// All events of one type across every campaign, in append order —
    /// the workspace-wide precedent lookup (`preference.answered` /
    /// `preference.revoked` events live in campaign records but carry
    /// authority across campaigns).
    pub fn list_events_of_type(&self, event_type: &str) -> StoreResult<Vec<CampaignEventRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT campaign_id, seq, event_type, payload_json, created_at
                 FROM campaign_events WHERE event_type = ?1 ORDER BY campaign_id, seq",
            )
            .map_err(StoreError::from)?;
        let rows = statement
            .query_map(params![event_type], campaign_event_from_row)
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        Ok(rows)
    }

    /// Fold every campaign's event log into a head-line summary.
    pub fn list_campaigns(&self) -> StoreResult<Vec<CampaignSummary>> {
        // The fold reads payloads only for `campaign.opened` (the spec) and
        // `campaign.spend` (one integer); everything else — notably
        // `candidate.recorded`, which embeds full candidate sources — stays
        // unfetched and unparsed.
        let mut statement = self
            .connection
            .prepare(
                "SELECT campaign_id, seq, event_type,
                   CASE WHEN event_type IN ('campaign.opened', 'campaign.spend')
                        THEN payload_json ELSE '{}' END,
                   created_at
                 FROM campaign_events ORDER BY campaign_id, seq",
            )
            .map_err(StoreError::from)?;
        let rows = statement
            .query_map([], campaign_event_from_row)
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        let mut summaries: Vec<CampaignSummary> = Vec::new();
        for event in rows {
            if summaries
                .last()
                .map(|s: &CampaignSummary| s.campaign_id != event.campaign_id)
                .unwrap_or(true)
            {
                summaries.push(CampaignSummary {
                    campaign_id: event.campaign_id.clone(),
                    status: "open".to_owned(),
                    spec: Value::Null,
                    opened_at: event.created_at.clone(),
                    last_event_at: event.created_at.clone(),
                    candidates: 0,
                    proposed: 0,
                    spent_micros: 0,
                });
            }
            let summary = summaries
                .last_mut()
                .expect("summary pushed for this campaign id");
            fold_campaign_event(summary, &event);
        }
        Ok(summaries)
    }
}

#[cfg(feature = "native")]
fn scenario_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScenarioRow> {
    Ok(ScenarioRow {
        name: row.get(0)?,
        instance_id: row.get(1)?,
        workflow: row.get(2)?,
        input_json: row.get(3)?,
        program_hash: row.get(4)?,
        mark: row.get(5)?,
        cut_sequence: row.get(6)?,
        store_path: row.get(7)?,
        pinned_at: row.get(8)?,
        retired: row.get::<_, i64>(9)? != 0,
        wear: row.get(10)?,
    })
}

#[cfg(feature = "native")]
fn campaign_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CampaignEventRow> {
    let payload_json: String = row.get(3)?;
    Ok(CampaignEventRow {
        campaign_id: row.get(0)?,
        seq: row.get(1)?,
        event_type: row.get(2)?,
        payload: serde_json::from_str(&payload_json).unwrap_or(Value::Null),
        created_at: row.get(4)?,
    })
}

/// The campaign fold, shared by listing and detail views: how one event
/// advances the head-line state.
pub fn fold_campaign_event(summary: &mut CampaignSummary, event: &CampaignEventRow) {
    summary.last_event_at = event.created_at.clone();
    match event.event_type.as_str() {
        "campaign.opened" => {
            summary.spec = event.payload.clone();
            summary.opened_at = event.created_at.clone();
        }
        "candidate.recorded" => summary.candidates += 1,
        "candidate.proposed" => summary.proposed += 1,
        "campaign.spend" => {
            if let Some(micros) = event.payload.get("cost_micros").and_then(Value::as_i64) {
                summary.spent_micros += micros;
            }
        }
        "campaign.parked" => summary.status = "parked".to_owned(),
        "campaign.resumed" => summary.status = "open".to_owned(),
        "campaign.closed" => summary.status = "closed".to_owned(),
        "candidate.adopted" => summary.status = "adopted".to_owned(),
        _ => {}
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn evidence_appends_and_filters() {
        let mut store = ImproveStore::open_in_memory().expect("open");
        store
            .record_evidence(NewEvidence {
                gauge: "extract_quality",
                score: 1.0,
                passed: Some(true),
                execution_mode: "live",
                scorer: "exec:./judge.py",
                ..Default::default()
            })
            .expect("record");
        store
            .record_evidence(NewEvidence {
                gauge: "std.latency",
                score: 812.0,
                execution_mode: "regen",
                scorer: "builtin",
                campaign_id: Some("C-1"),
                candidate_id: Some("K-1"),
                ..Default::default()
            })
            .expect("record");
        let all = store.list_evidence(None, None, None, None).expect("list");
        assert_eq!(all.len(), 2);
        let campaign = store
            .list_evidence(None, Some("C-1"), None, None)
            .expect("list");
        assert_eq!(campaign.len(), 1);
        assert_eq!(campaign[0].gauge, "std.latency");
        assert_eq!(
            store.evidence_gauges().expect("gauges"),
            vec!["extract_quality".to_owned(), "std.latency".to_owned()]
        );
    }

    #[test]
    fn unknown_execution_mode_refused() {
        let mut store = ImproveStore::open_in_memory().expect("open");
        let err = store
            .record_evidence(NewEvidence {
                gauge: "g",
                score: 0.0,
                execution_mode: "counterfactual",
                scorer: "builtin",
                ..Default::default()
            })
            .expect_err("mode should be refused");
        assert!(format!("{err:?}").contains("unknown execution mode"));
    }

    #[test]
    fn scenario_pin_wear_and_retirement() {
        let mut store = ImproveStore::open_in_memory().expect("open");
        store
            .pin_scenario(
                "subject-line",
                "inst-1",
                Some("Triage"),
                "{}",
                None,
                None,
                None,
                None,
            )
            .expect("pin");
        let dup = store.pin_scenario("subject-line", "inst-2", None, "{}", None, None, None, None);
        assert!(dup.is_err(), "duplicate pin must be refused");
        assert_eq!(
            store.bump_scenario_wear("subject-line", 3).expect("wear"),
            1
        );
        assert_eq!(
            store.bump_scenario_wear("subject-line", 3).expect("wear"),
            2
        );
        let row = store
            .get_scenario("subject-line")
            .expect("get")
            .expect("present");
        assert!(!row.retired);
        assert_eq!(
            store.bump_scenario_wear("subject-line", 3).expect("wear"),
            3
        );
        let row = store
            .get_scenario("subject-line")
            .expect("get")
            .expect("present");
        assert!(row.retired, "kmax gate exposures retire the scenario");
        assert_eq!(row.wear, 3);
    }

    #[test]
    fn campaign_record_folds() {
        let mut store = ImproveStore::open_in_memory().expect("open");
        let id = store
            .open_campaign(&json!({"ascend": ["extract_quality"]}))
            .expect("open campaign");
        assert_eq!(id, "C-1");
        store
            .append_campaign_event(&id, "candidate.recorded", &json!({"candidate": "K-1"}))
            .expect("append");
        store
            .append_campaign_event(&id, "campaign.spend", &json!({"cost_micros": 250}))
            .expect("append");
        store
            .append_campaign_event(&id, "candidate.proposed", &json!({"candidate": "K-1"}))
            .expect("append");
        let campaigns = store.list_campaigns().expect("list");
        assert_eq!(campaigns.len(), 1);
        let head = &campaigns[0];
        assert_eq!(head.campaign_id, "C-1");
        assert_eq!(head.status, "open");
        assert_eq!(head.candidates, 1);
        assert_eq!(head.proposed, 1);
        assert_eq!(head.spent_micros, 250);
        assert_eq!(head.spec["ascend"][0], "extract_quality");
        let events = store.list_campaign_events(&id).expect("events");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, "campaign.opened");
    }
}
