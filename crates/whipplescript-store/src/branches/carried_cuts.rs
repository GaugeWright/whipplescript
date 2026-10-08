//! The registry of cut carriages a store has sent or received (DR-0139, FB-6).
//!
//! A carriage is keyed by its content digest, never by a cut id, because cut
//! ids are minted per host. The registry is what makes a carriage *recorded*
//! rather than merely present: it names the stored header and every step's
//! manifest, so the content collector keeps what a carriage reaches, and it
//! says which way the carriage went, so a Home receives a returned line only
//! against a carriage it sent and a peer returns one only against a carriage it
//! received. It holds no ref and moves none.

use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS carried_cuts (
        digest TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        direction TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS carried_cut_steps (
        digest TEXT NOT NULL,
        step INTEGER NOT NULL,
        manifest_hash TEXT NOT NULL,
        PRIMARY KEY (digest, step)
    )",
];

/// Which way a carriage went, from this store's side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarriageDirection {
    /// This store exported it.
    Sent,
    /// This store recorded it from another host.
    Received,
}

impl CarriageDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }

    pub fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "sent" => Ok(Self::Sent),
            "received" => Ok(Self::Received),
            other => Err(crate::StoreError::Conflict(format!(
                "carried cut row has unknown direction `{other}`"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarriedCutRow {
    pub digest: String,
    /// The content id of the stored canonical header.
    pub record_id: String,
    /// The header's kind, as its wire name.
    pub kind: String,
    pub direction: CarriageDirection,
    /// This store's manifest root for each step, oldest first.
    pub step_manifest_hashes: Vec<String>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordCarriageOutcome {
    Recorded,
    /// The digest was already recorded; the existing row is returned and
    /// nothing was written.
    AlreadyRecorded(CarriedCutRow),
}

pub trait CarriedCuts {
    /// Record a carriage by digest, atomically with its steps. A digest that is
    /// already recorded answers with the existing row.
    fn record_carriage(&mut self, row: &CarriedCutRow) -> StoreResult<RecordCarriageOutcome>;
    fn carriage(&self, digest: &str) -> StoreResult<Option<CarriedCutRow>>;
}

#[cfg(feature = "native")]
mod native {
    use rusqlite::{params, OptionalExtension, TransactionBehavior};

    use super::{CarriageDirection, CarriedCutRow, CarriedCuts, RecordCarriageOutcome};
    use crate::branches::BranchStore;
    use crate::StoreResult;

    fn read(connection: &rusqlite::Connection, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
        let Some((record_id, kind, direction, recorded_at)) = connection
            .query_row(
                "SELECT record_id, kind, direction, recorded_at FROM carried_cuts \
                 WHERE digest = ?1",
                params![digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT manifest_hash FROM carried_cut_steps WHERE digest = ?1 ORDER BY step",
        )?;
        let step_manifest_hashes = statement
            .query_map(params![digest], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(CarriedCutRow {
            digest: digest.to_owned(),
            record_id,
            kind,
            direction: CarriageDirection::parse(&direction)?,
            step_manifest_hashes,
            recorded_at,
        }))
    }

    impl CarriedCuts for BranchStore {
        fn record_carriage(&mut self, row: &CarriedCutRow) -> StoreResult<RecordCarriageOutcome> {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(existing) = read(&tx, &row.digest)? {
                return Ok(RecordCarriageOutcome::AlreadyRecorded(existing));
            }
            tx.execute(
                "INSERT INTO carried_cuts (digest, record_id, kind, direction, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    row.digest,
                    row.record_id,
                    row.kind,
                    row.direction.as_str(),
                    row.recorded_at
                ],
            )?;
            for (step, manifest_hash) in row.step_manifest_hashes.iter().enumerate() {
                tx.execute(
                    "INSERT INTO carried_cut_steps (digest, step, manifest_hash) \
                     VALUES (?1, ?2, ?3)",
                    params![row.digest, step as i64, manifest_hash],
                )?;
            }
            tx.commit()?;
            Ok(RecordCarriageOutcome::Recorded)
        }

        fn carriage(&self, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
            read(&self.connection, digest)
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::branches::BranchStore;

    #[test]
    fn a_row_records_once_and_reads_back_with_its_steps() {
        let dir = crate::scratch::path("whipplescript-carried-cuts-registry");
        let mut store = BranchStore::open(dir.join("branches.sqlite")).expect("open");
        let row = CarriedCutRow {
            digest: "d1".to_owned(),
            record_id: "r1".to_owned(),
            kind: "prefix".to_owned(),
            direction: CarriageDirection::Received,
            step_manifest_hashes: vec!["m0".to_owned(), "m1".to_owned()],
            recorded_at: "t0".to_owned(),
        };
        assert_eq!(
            store.record_carriage(&row).expect("record"),
            RecordCarriageOutcome::Recorded
        );
        assert_eq!(store.carriage("d1").expect("read"), Some(row.clone()));
        let mut again = row.clone();
        again.recorded_at = "t1".to_owned();
        assert_eq!(
            store.record_carriage(&again).expect("again"),
            RecordCarriageOutcome::AlreadyRecorded(row)
        );
        assert_eq!(store.carriage("d2").expect("read"), None);

        store
            .connection
            .execute(
                "UPDATE carried_cuts SET direction = 'sideways' WHERE digest = 'd1'",
                [],
            )
            .expect("corrupt");
        let error = store.carriage("d1").expect_err("an unknown direction");
        assert!(
            format!("{error:?}").contains("unknown direction"),
            "{error:?}"
        );
    }
}
