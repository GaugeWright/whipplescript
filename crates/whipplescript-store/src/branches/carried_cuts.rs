//! The registry of cut carriages a store has sent or received (DR-0139, FB-6).
//!
//! A carriage is keyed by its content digest, never by a cut id, because cut
//! ids are minted per host. The registry is what makes a carriage *recorded*
//! rather than merely present: it names the stored header and every step's
//! manifest, so the content collector keeps what a carriage reaches, and it
//! says which way the carriage went, so a Home receives a returned line only
//! against a carriage it sent and a peer returns one only against a carriage it
//! received. It holds no ref and moves none.

use crate::branches::{BranchRow, CutRow, OpRow, MAINLINE_BRANCH_ID};
use crate::{StoreError, StoreResult};

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

/// One peer-local twig seeded from a received carriage. The expected parent
/// head fixes the local branch point; the carried digest fixes the seed tree.
/// The cut id is minted in the peer's namespace, not imported from the Home.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeedCarriedTwig<'a> {
    pub twig_branch_id: &'a str,
    pub expected_parent_cut_id: Option<&'a str>,
    pub seed_cut_id: &'a str,
    pub carriage_digest: &'a str,
    pub head_manifest_hash: &'a str,
    pub actor: &'a str,
    pub intent: &'a str,
    pub recorded_at: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarriedTwigSeedReceipt {
    pub twig_branch_id: String,
    pub parent_cut_id: Option<String>,
    pub seed_cut_id: String,
    pub carriage_digest: String,
    pub head_manifest_hash: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SeedCarriedTwigOutcome {
    Seeded(CarriedTwigSeedReceipt),
    AlreadySeeded(CarriedTwigSeedReceipt),
}

pub fn seed_origin(digest: &str) -> String {
    format!("carried-seed:{digest}")
}

/// A retry may find a twig with later peer work. Its immutable seed cut and
/// operation must still agree exactly with the original creation and request.
pub fn existing_seed(
    branch: Option<&BranchRow>,
    cut: Option<&CutRow>,
    op: Option<&OpRow>,
    request: SeedCarriedTwig<'_>,
) -> StoreResult<Option<CarriedTwigSeedReceipt>> {
    let (Some(branch), Some(cut), Some(op)) = (branch, cut, op) else {
        if branch.is_some() || cut.is_some() || op.is_some() {
            return Err(StoreError::Conflict(
                "carried twig seed has partial custody".into(),
            ));
        }
        return Ok(None);
    };
    let origin = seed_origin(request.carriage_digest);
    let Some(delta) = op.deltas.as_slice().first() else {
        return Err(StoreError::Conflict(
            "carried twig seed has no operation delta".into(),
        ));
    };
    if op.kind != "carried-seed"
        || op.op_id != format!("op-{}", request.seed_cut_id)
        || op.origin.as_deref() != Some(origin.as_str())
        || op.deltas.len() != 1
        || delta.before.is_some()
        || delta.branch_id != request.twig_branch_id
        || delta.after.head_cut_id.as_deref() != Some(request.seed_cut_id)
        || delta.after.head_manifest_hash.as_deref() != Some(request.head_manifest_hash)
        || delta.after.branch_point_cut_id.as_deref() != request.expected_parent_cut_id
        || delta.after.branch_point_manifest_hash != branch.branch_point_manifest_hash
        || delta.after.status != crate::branches::BranchStatus::Active
        || branch.branch_id != request.twig_branch_id
        || branch.name.is_some()
        || branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        || branch.branch_point_cut_id.as_deref() != request.expected_parent_cut_id
        || branch.created_at != cut.recorded_at
        || cut.cut_id != request.seed_cut_id
        || cut.change_id != request.seed_cut_id
        || cut.branch_id != request.twig_branch_id
        || cut.manifest_hash != request.head_manifest_hash
        || cut.parent_cut_id.as_deref() != request.expected_parent_cut_id
        || cut.origin.as_deref() != Some(origin.as_str())
        || cut.actor.as_deref() != Some(request.actor)
        || cut.intent.as_deref() != Some(request.intent)
        || op.recorded_at != cut.recorded_at
    {
        return Err(StoreError::Conflict(
            "carried twig seed retry changes its meaning".into(),
        ));
    }
    Ok(Some(CarriedTwigSeedReceipt {
        twig_branch_id: branch.branch_id.clone(),
        parent_cut_id: cut.parent_cut_id.clone(),
        seed_cut_id: cut.cut_id.clone(),
        carriage_digest: request.carriage_digest.to_owned(),
        head_manifest_hash: cut.manifest_hash.clone(),
        recorded_at: cut.recorded_at.clone(),
    }))
}

pub trait CarriedCuts {
    /// Record a carriage by digest, atomically with its steps. A digest that is
    /// already recorded answers with the existing row.
    fn record_carriage(&mut self, row: &CarriedCutRow) -> StoreResult<RecordCarriageOutcome>;
    fn carriage(&self, digest: &str) -> StoreResult<Option<CarriedCutRow>>;

    /// Publish branch, seed cut, and immutable operation receipt in one
    /// transaction. Unsupported backends refuse rather than split the write.
    fn seed_carried_twig(
        &mut self,
        _request: SeedCarriedTwig<'_>,
    ) -> StoreResult<SeedCarriedTwigOutcome> {
        Err(StoreError::Conflict(
            "atomic carried twig seeding is unavailable".into(),
        ))
    }
}

#[cfg(feature = "native")]
mod native {
    use rusqlite::{params, OptionalExtension, TransactionBehavior};

    use super::{
        existing_seed, seed_origin, CarriageDirection, CarriedCutRow, CarriedCuts,
        CarriedTwigSeedReceipt, RecordCarriageOutcome, SeedCarriedTwig, SeedCarriedTwigOutcome,
    };
    use crate::branches::{
        map_op_row, write_commit, BranchStatus, BranchStore, OpBranchDelta, OpBranchState,
        MAINLINE_BRANCH_ID,
    };
    use crate::{StoreError, StoreResult};

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

        fn seed_carried_twig(
            &mut self,
            request: SeedCarriedTwig<'_>,
        ) -> StoreResult<SeedCarriedTwigOutcome> {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let branch = BranchStore::row_by_id(&tx, request.twig_branch_id)?;
            let cut = BranchStore::cut_by_id(&tx, request.seed_cut_id)?;
            let op = tx
                .prepare_cached(
                    "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops WHERE op_id = ?1",
                )?
                .query_row([format!("op-{}", request.seed_cut_id)], map_op_row)
                .optional()?
                .transpose()?;
            if let Some(receipt) =
                existing_seed(branch.as_ref(), cut.as_ref(), op.as_ref(), request)?
            {
                tx.commit()?;
                return Ok(SeedCarriedTwigOutcome::AlreadySeeded(receipt));
            }
            let carried = read(&tx, request.carriage_digest)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed has no received carriage".into())
            })?;
            if carried.direction != CarriageDirection::Received
                || carried.kind == "peer_line"
                || carried.step_manifest_hashes.last().map(String::as_str)
                    != Some(request.head_manifest_hash)
            {
                return Err(StoreError::Conflict(
                    "carried twig seed does not match a received cut or prefix".into(),
                ));
            }
            let parent = BranchStore::row_by_id(&tx, MAINLINE_BRANCH_ID)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed has no local mainline".into())
            })?;
            if parent.status != BranchStatus::Active
                || parent.head_cut_id.as_deref() != request.expected_parent_cut_id
            {
                return Err(StoreError::Conflict(
                    "carried twig seed has a stale local parent".into(),
                ));
            }
            let origin = seed_origin(request.carriage_digest);
            tx.execute(
                "INSERT INTO branches (branch_id, name, parent_branch_id, branch_point_cut_id, \
                 branch_point_manifest_hash, head_cut_id, head_manifest_hash, status, created_at, updated_at) \
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?7)",
                params![request.twig_branch_id, MAINLINE_BRANCH_ID, parent.head_cut_id,
                    parent.head_manifest_hash, request.seed_cut_id, request.head_manifest_hash,
                    request.recorded_at],
            )?;
            tx.execute(
                write_commit::INSERT_CUT,
                params![
                    request.seed_cut_id,
                    request.seed_cut_id,
                    request.twig_branch_id,
                    request.head_manifest_hash,
                    request.expected_parent_cut_id,
                    origin,
                    request.actor,
                    request.intent,
                    request.recorded_at
                ],
            )?;
            let after = BranchStore::row_by_id(&tx, request.twig_branch_id)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed branch disappeared".into())
            })?;
            let deltas = serde_json::to_string(&[OpBranchDelta {
                branch_id: request.twig_branch_id.to_owned(),
                before: None,
                after: OpBranchState::of(&after),
            }])?;
            tx.execute(
                write_commit::INSERT_OP,
                params![
                    format!("op-{}", request.seed_cut_id),
                    "carried-seed",
                    deltas,
                    seed_origin(request.carriage_digest),
                    request.recorded_at
                ],
            )?;
            tx.commit()?;
            Ok(SeedCarriedTwigOutcome::Seeded(CarriedTwigSeedReceipt {
                twig_branch_id: request.twig_branch_id.to_owned(),
                parent_cut_id: request.expected_parent_cut_id.map(str::to_owned),
                seed_cut_id: request.seed_cut_id.to_owned(),
                carriage_digest: request.carriage_digest.to_owned(),
                head_manifest_hash: request.head_manifest_hash.to_owned(),
                recorded_at: request.recorded_at.to_owned(),
            }))
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod seed_contract_tests {
    use super::*;
    use crate::branches::{BranchStore, Branches};

    fn received() -> CarriedCutRow {
        CarriedCutRow {
            digest: "received".into(),
            record_id: "header".into(),
            kind: "cut".into(),
            direction: CarriageDirection::Received,
            step_manifest_hashes: vec!["manifest".into()],
            recorded_at: "t0".into(),
        }
    }

    fn request() -> SeedCarriedTwig<'static> {
        SeedCarriedTwig {
            twig_branch_id: "twig",
            expected_parent_cut_id: None,
            seed_cut_id: "seed",
            carriage_digest: "received",
            head_manifest_hash: "manifest",
            actor: "agent:peer",
            intent: "turn:one",
            recorded_at: "t1",
        }
    }

    fn refused(result: StoreResult<SeedCarriedTwigOutcome>, words: &str) {
        let error = result.expect_err("backend must refuse");
        assert!(format!("{error:?}").contains(words), "{error:?}");
    }

    #[test]
    fn native_backend_refuses_missing_carriage_parent_and_lost_branch() {
        let path = crate::scratch::file("carried-native-backend", "sqlite");
        let mut store = BranchStore::open(&path).expect("store");
        store.ensure_mainline("t0").expect("mainline");
        refused(store.seed_carried_twig(request()), "no received carriage");
        store.record_carriage(&received()).expect("received row");
        refused(
            store.seed_carried_twig(SeedCarriedTwig {
                head_manifest_hash: "other",
                ..request()
            }),
            "does not match a received cut or prefix",
        );
        store
            .connection
            .execute(
                "UPDATE branches SET head_cut_id = 'later' WHERE branch_id = 'main'",
                [],
            )
            .expect("move mainline");
        refused(store.seed_carried_twig(request()), "stale local parent");
        store
            .connection
            .execute(
                "UPDATE branches SET head_cut_id = NULL WHERE branch_id = 'main'",
                [],
            )
            .expect("restore mainline");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER lose_seed_branch AFTER INSERT ON branches \
                 WHEN NEW.branch_id = 'twig' BEGIN DELETE FROM branches WHERE branch_id = 'twig'; END",
            )
            .expect("inject branch loss");
        refused(store.seed_carried_twig(request()), "branch disappeared");
        assert!(store.get_branch("twig").expect("twig").is_none());
        assert!(store.get_cut("seed").expect("cut").is_none());
        assert!(store.get_op("op-seed").expect("op").is_none());

        let mut without_mainline =
            BranchStore::open(crate::scratch::file("carried-no-mainline", "sqlite"))
                .expect("store without mainline");
        without_mainline
            .record_carriage(&received())
            .expect("received row");
        refused(
            without_mainline.seed_carried_twig(request()),
            "no local mainline",
        );
    }

    #[test]
    fn unsupported_backend_refuses_atomic_seed() {
        struct Unsupported;
        impl CarriedCuts for Unsupported {
            fn record_carriage(
                &mut self,
                _row: &CarriedCutRow,
            ) -> StoreResult<RecordCarriageOutcome> {
                unreachable!()
            }
            fn carriage(&self, _digest: &str) -> StoreResult<Option<CarriedCutRow>> {
                unreachable!()
            }
        }
        refused(
            Unsupported.seed_carried_twig(request()),
            "atomic carried twig seeding is unavailable",
        );
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
