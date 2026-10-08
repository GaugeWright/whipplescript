//! Carrying cuts between a Home and its hosted peers (DR-0139, FB-6).
//!
//! A hosted object is an execution peer of its Home. The Home ships an exact
//! cut, or a prefix of cuts, to the peer as a **content-addressed bundle**,
//! and the peer records it by that content: cut ids are minted per host, so
//! an id the Home chose names nothing on the peer, and nothing here writes a
//! Home's cut into a peer's refs. The reverse direction is the same carrier:
//! a line the peer wrote against a carried cut returns to the Home as a
//! recorded candidate, and the Home records it by content without moving any
//! ref. Admission of that candidate to a trunk is DR-0130's gate and
//! GaugeWright DR-0171's review door, never this module.
//!
//! The bundle's identity is a SHA-256 digest over a canonical header: the
//! format, what kind of carriage it is, the base it was written against (for a
//! returned line), each step's path-to-content-id map, and the SHA-256 of every
//! file's bytes. The store's content ids are SHA-256 truncated to 128 bits
//! (`chunking::content_hash_hex` and `stable_hash_bytes_hex`); the full file
//! digest binds the carried bytes independently of that shorter dedup id.
//! Host cut ids and change ids travel beside
//! the header as advisory provenance: they are outside the digest because they
//! differ between hosts, and they grant nothing.
//!
//! Recording writes content and one registry row (`branches::carried_cuts`),
//! never a branch, cut or head. The header's canonical bytes are stored as a
//! content blob and the row names it and every step's manifest by digest, so
//! the content collector keeps what a recorded carriage reaches, and
//! re-recording the same carriage is `AlreadyRecorded`. Verification is
//! complete before the first write: a bundle that fails any check leaves the
//! receiving store as it found it.

use super::*;
use crate::branches::carried_cuts::{
    existing_seed, CarriageDirection, CarriedCutRow, CarriedCuts, RecordCarriageOutcome,
    SeedCarriedTwig, SeedCarriedTwigOutcome,
};
use crate::bundle::BundleBlob;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The carrier's wire format. A reader refuses any other.
pub const CARRIED_CUT_FORMAT: &str = "whipplescript.carried-cut.v1";

/// What a carriage carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarriedKind {
    /// One exact cut: a single step.
    Cut,
    /// The dependency-closed prefix under check: the base cut it applies to,
    /// then every cut through the selected head, oldest first.
    Prefix,
    /// A line a peer wrote against a carriage it was supplied, returning to
    /// the Home as a candidate: every cut after the base, oldest first.
    PeerLine,
}

/// The digest-bound part of a carriage. Its canonical JSON is what the digest
/// covers and what a receiving store records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedHeader {
    pub format: String,
    pub kind: CarriedKind,
    /// The digest of the carriage a returned line was written against.
    /// Present exactly when `kind` is `PeerLine`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Each step's whole manifest, path to content id, oldest first.
    pub steps: Vec<BTreeMap<String, String>>,
    /// SHA-256 of the bytes behind every content id the steps reference.
    pub file_digests: BTreeMap<String, String>,
}

/// Where the carried cuts came from on the sending host. Advisory: outside the
/// digest, never a key, never an authority.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedProvenance {
    /// The sending host's cut id for each step, aligned with `steps`.
    #[serde(default)]
    pub host_cut_ids: Vec<String>,
    /// The change id each step's cut carries, aligned with `steps`.
    #[serde(default)]
    pub change_ids: Vec<Option<String>>,
}

/// A carriage on the wire: header, its declared digest, provenance and the
/// blobs every step reaches. Always complete; it has no delta form.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedCut {
    pub digest: String,
    pub header: CarriedHeader,
    #[serde(default)]
    pub provenance: CarriedProvenance,
    pub blobs: Vec<BundleBlob>,
}

/// What a store holds once it has registered a carriage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarriedReceipt {
    pub digest: String,
    /// The content id of the stored canonical header.
    pub record_id: String,
    pub kind: CarriedKind,
    pub direction: CarriageDirection,
    /// This store's manifest root for the last step: its own layout, which is
    /// why it is not part of the digest.
    pub head_manifest_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CarriageOutcome {
    Recorded(CarriedReceipt),
    /// This store already registered exactly this carriage, in the same
    /// direction. Nothing was written.
    AlreadyRecorded(CarriedReceipt),
}

impl CarriageOutcome {
    pub fn receipt(&self) -> &CarriedReceipt {
        match self {
            Self::Recorded(receipt) | Self::AlreadyRecorded(receipt) => receipt,
        }
    }
}

impl CarriedKind {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Cut => "cut",
            Self::Prefix => "prefix",
            Self::PeerLine => "peer_line",
        }
    }
}

fn receipt_of(row: &CarriedCutRow, kind: CarriedKind) -> CarriedReceipt {
    CarriedReceipt {
        digest: row.digest.clone(),
        record_id: row.record_id.clone(),
        kind,
        direction: row.direction,
        head_manifest_hash: row.step_manifest_hashes.last().cloned().unwrap_or_default(),
    }
}

/// A carriage this store already registered answers as already recorded only
/// in the direction it went: a store that sent a carriage has not received it.
fn already_recorded(
    existing: CarriedCutRow,
    wanted: CarriageDirection,
    kind: CarriedKind,
) -> StoreResult<CarriageOutcome> {
    if existing.direction != wanted {
        return refuse(format!(
            "this store already {} carriage `{}`",
            existing.direction.as_str(),
            existing.digest
        ));
    }
    Ok(CarriageOutcome::AlreadyRecorded(receipt_of(
        &existing, kind,
    )))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn refuse<T>(reason: impl Into<String>) -> StoreResult<T> {
    Err(StoreError::Conflict(format!(
        "carried cut refused: {}",
        reason.into()
    )))
}

fn retained_manifest<C: ContentBlobs>(
    content: &C,
    root_hash: &str,
) -> StoreResult<BTreeMap<String, String>> {
    let Some(body) = content.get_text(root_hash)?.text() else {
        return refuse(format!(
            "carried step manifest `{root_hash}` is unavailable"
        ));
    };
    if let Some(root) = crate::manifest_tree::parse_node(&body) {
        return crate::manifest_tree::load_from(content, root);
    }
    Ok(serde_json::from_str(&body)?)
}

impl CarriedHeader {
    /// The canonical bytes the digest covers and a store records. Every map is
    /// a `BTreeMap`, so serialization order is the content's own order.
    pub fn canonical_bytes(&self) -> StoreResult<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn digest(&self) -> StoreResult<String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    fn check_shape(&self) -> StoreResult<()> {
        if self.format != CARRIED_CUT_FORMAT {
            return refuse(format!("unknown format `{}`", self.format));
        }
        match (self.kind, self.base.is_some(), self.steps.len()) {
            (_, _, 0) => return refuse("it carries no step"),
            (CarriedKind::Cut, false, 1) => {}
            (CarriedKind::Cut, _, _) => {
                return refuse("a cut carries exactly one step and no base")
            }
            (CarriedKind::Prefix, false, steps) if steps >= 2 => {}
            (CarriedKind::Prefix, _, _) => {
                return refuse("a prefix carries its base and at least one cut, and no peer base")
            }
            (CarriedKind::PeerLine, true, _) => {}
            (CarriedKind::PeerLine, false, _) => {
                return refuse("a peer line names the carriage it was written against")
            }
        }
        let mut referenced = BTreeSet::new();
        for step in &self.steps {
            for (path, id) in step {
                crate::materialize::validate_manifest_key(path)?;
                referenced.insert(id.as_str());
            }
        }
        if !referenced
            .iter()
            .copied()
            .eq(self.file_digests.keys().map(String::as_str))
        {
            return refuse("its file digests do not cover exactly the content its steps reference");
        }
        Ok(())
    }
}

/// Decode and verify every carried body in memory, before anything is written:
/// plain blobs against their content ids, chunk roots against their chunk
/// lists, and every referenced file's reassembled bytes against the header's
/// SHA-256. Returns the bytes by unit id, in the order to store them.
struct VerifiedBlobs {
    plain: Vec<(String, Vec<u8>)>,
    roots: Vec<(String, Vec<String>, u64)>,
}

fn verify_blobs(header: &CarriedHeader, blobs: &[BundleBlob]) -> StoreResult<VerifiedBlobs> {
    let max_blob_bytes = crate::content::max_blob_bytes();
    let mut plain = BTreeMap::new();
    let mut roots = BTreeMap::new();
    for blob in blobs {
        if blob.erased || blob.omitted {
            return refuse(format!(
                "`{}` travels without its bytes; a carriage is complete or it is not one",
                blob.id
            ));
        }
        if let Some(chunk_ids) = &blob.chunk_ids {
            if blob.byte_len > max_blob_bytes {
                return refuse(format!(
                    "chunk root `{}` declares {} bytes, over the {max_blob_bytes}-byte ceiling",
                    blob.id, blob.byte_len
                ));
            }
            let joined: Vec<u8> = chunk_ids
                .iter()
                .flat_map(|chunk| chunk.as_bytes().iter().copied())
                .collect();
            if crate::chunking::content_hash_hex(&joined) != blob.id {
                return refuse(format!(
                    "chunk root `{}` does not match its chunk list",
                    blob.id
                ));
            }
            if roots
                .insert(blob.id.clone(), (chunk_ids.clone(), blob.byte_len))
                .is_some()
            {
                return refuse(format!("`{}` is carried twice", blob.id));
            }
            continue;
        }
        let Some(bytes) = blob.carried_bytes()? else {
            return refuse(format!("`{}` carries no body", blob.id));
        };
        crate::content::verify_body(&blob.id, &bytes, "carried cut")?;
        if plain.insert(blob.id.clone(), bytes).is_some() {
            return refuse(format!("`{}` is carried twice", blob.id));
        }
    }
    let mut needed = BTreeSet::new();
    for (id, expected) in &header.file_digests {
        let bytes = if let Some((chunk_ids, byte_len)) = roots.get(id) {
            let mut whole = Vec::new();
            for chunk in chunk_ids {
                let Some(part) = plain.get(chunk) else {
                    return refuse(format!("chunk `{chunk}` of `{id}` is not carried"));
                };
                whole.extend_from_slice(part);
                needed.insert(chunk.clone());
            }
            if whole.len() as u64 != *byte_len {
                return refuse(format!("chunk root `{id}` reassembles to a different size"));
            }
            whole
        } else if let Some(bytes) = plain.get(id) {
            bytes.clone()
        } else {
            return refuse(format!("referenced content `{id}` is not carried"));
        };
        needed.insert(id.clone());
        if &sha256_hex(&bytes) != expected {
            return refuse(format!(
                "the bytes carried for `{id}` are not the bytes the digest names"
            ));
        }
    }
    let carried: BTreeSet<String> = plain.keys().chain(roots.keys()).cloned().collect();
    if carried != needed {
        return refuse("it carries blobs no step reaches");
    }
    Ok(VerifiedBlobs {
        plain: plain.into_iter().collect(),
        roots: roots
            .into_iter()
            .map(|(id, (chunks, len))| (id, chunks, len))
            .collect(),
    })
}

impl<B: Branches + CarriedCuts, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Seed one peer-local direct twig from a received carriage. The carriage
    /// itself owns no ref; this operation publishes the twig, its local seed
    /// cut, and a recoverable receipt together while all carried bytes are
    /// retained. The peer mainline is only the local lineage parent.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_peer_twig(
        &mut self,
        digest: &str,
        twig_branch_id: &str,
        expected_parent_cut_id: Option<&str>,
        seed_cut_id: &str,
        actor: &str,
        intent: &str,
        at: &str,
    ) -> StoreResult<SeedCarriedTwigOutcome> {
        if twig_branch_id.is_empty()
            || twig_branch_id == MAINLINE_BRANCH_ID
            || seed_cut_id.is_empty()
            || actor.trim().is_empty()
            || intent.trim().is_empty()
        {
            return refuse("twig seed requires a distinct twig, local cut, actor and intent");
        }
        let (row, header) = self.recorded_carriage(digest)?;
        if row.direction != CarriageDirection::Received || header.kind == CarriedKind::PeerLine {
            return refuse("a peer twig can be seeded only from a received cut or prefix");
        }
        self.verified_carried_steps(digest)?;
        let head_manifest_hash = row
            .step_manifest_hashes
            .last()
            .expect("recorded_carriage checked a nonempty step registry");
        let mut retained = vec![row.record_id.clone()];
        retained.extend(row.step_manifest_hashes.iter().cloned());
        retained.extend(header.file_digests.keys().cloned());
        let content = &self.content;
        let branches = &mut self.branches;
        content.publish_retained(&retained, || {
            let Some(stored_header) = content.get(&row.record_id)? else {
                return refuse("carried twig seed lost its recorded header");
            };
            if sha256_hex(&stored_header) != digest || stored_header != header.canonical_bytes()? {
                return refuse("carried twig seed header differs from its digest");
            }
            for (step, hash) in header.steps.iter().zip(&row.step_manifest_hashes) {
                if retained_manifest(content, hash)? != *step {
                    return refuse("carried twig seed has a mismatched retained step");
                }
            }
            for (id, expected) in &header.file_digests {
                let Some(bytes) = content.get(id)? else {
                    return refuse(format!("carried content `{id}` is unavailable"));
                };
                if &sha256_hex(&bytes) != expected {
                    return refuse(format!("carried content `{id}` differs from the carriage"));
                }
            }
            branches
                .seed_carried_twig(SeedCarriedTwig {
                    twig_branch_id,
                    expected_parent_cut_id,
                    seed_cut_id,
                    carriage_digest: digest,
                    head_manifest_hash,
                    actor,
                    intent,
                    recorded_at: at,
                })
                .map_err(|error| match error {
                    StoreError::Conflict(reason) => {
                        StoreError::Conflict(format!("carried cut refused: {reason}"))
                    }
                    other => other,
                })
        })
    }

    /// Ship one exact recorded cut. The carriage is registered here as sent,
    /// so a line a peer returns against it can be checked against what this
    /// host actually supplied. Moves no ref.
    pub fn export_carried_cut(
        &mut self,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<(CarriedCut, CarriedReceipt)> {
        let Some(cut) = self.branches.get_cut(cut_id)? else {
            return refuse(format!("cut `{cut_id}` is not recorded"));
        };
        self.export_carriage(CarriedKind::Cut, None, vec![cut], at)
    }

    /// Ship the prefix from `base_cut_id` (the cut it applies to) through
    /// `head_cut_id`, inclusive, oldest first, along recorded parent pointers.
    pub fn export_carried_prefix(
        &mut self,
        base_cut_id: &str,
        head_cut_id: &str,
        at: &str,
    ) -> StoreResult<(CarriedCut, CarriedReceipt)> {
        if base_cut_id == head_cut_id {
            return refuse("a prefix needs at least one cut after its base");
        }
        let Some(chain) = self.cut_chain(head_cut_id, base_cut_id)? else {
            return refuse(format!(
                "`{head_cut_id}` does not descend from `{base_cut_id}` along recorded cuts"
            ));
        };
        self.export_carriage(CarriedKind::Prefix, None, chain, at)
    }

    /// The peer's half of the return path: the cuts on `branch_id` after
    /// `from_cut_id`, carried as a line written against the received carriage
    /// `base_digest`. `from_cut_id` must hold exactly that carriage's last
    /// step, which is what makes the line one written against it. Moves no ref.
    pub fn export_peer_line(
        &mut self,
        branch_id: &str,
        from_cut_id: &str,
        base_digest: &str,
        at: &str,
    ) -> StoreResult<(CarriedCut, CarriedReceipt)> {
        let (base_row, _) = self.recorded_carriage(base_digest)?;
        if base_row.direction != CarriageDirection::Received {
            return refuse("a peer line is written against a carriage the peer received");
        }
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return refuse(format!("branch `{branch_id}` does not exist"));
        };
        let head = branch.head_cut_id.clone().unwrap_or_default();
        if head == from_cut_id {
            return refuse("the line has no cut after its base");
        }
        let Some(mut chain) = self.cut_chain(&head, from_cut_id)? else {
            return refuse(format!(
                "`{branch_id}` does not descend from `{from_cut_id}`"
            ));
        };
        let from = chain.remove(0);
        let from_manifest = self.load_manifest(Some(&from.manifest_hash))?;
        if self.carried_head_manifest(base_digest)? != from_manifest {
            return refuse(format!(
                "`{from_cut_id}` does not hold the carriage the line names as its base"
            ));
        }
        let Some(seed_cut) = self.branches.get_cut(from_cut_id)? else {
            return refuse(format!("peer line base cut `{from_cut_id}` is missing"));
        };
        let seed_op = self.branches.get_op(&format!("op-{from_cut_id}"))?;
        let (Some(actor), Some(intent)) = (seed_cut.actor.as_deref(), seed_cut.intent.as_deref())
        else {
            return refuse("peer line base has no authenticated seed actor and intent");
        };
        if existing_seed(
            Some(&branch),
            Some(&seed_cut),
            seed_op.as_ref(),
            SeedCarriedTwig {
                twig_branch_id: branch_id,
                expected_parent_cut_id: seed_cut.parent_cut_id.as_deref(),
                seed_cut_id: from_cut_id,
                carriage_digest: base_digest,
                head_manifest_hash: &seed_cut.manifest_hash,
                actor,
                intent,
                recorded_at: &seed_cut.recorded_at,
            },
        )
        .is_err()
        {
            return refuse("peer line base has no exact atomic seed receipt");
        }
        self.export_carriage(
            CarriedKind::PeerLine,
            Some(base_digest.to_owned()),
            chain,
            at,
        )
    }

    fn export_carriage(
        &mut self,
        kind: CarriedKind,
        base: Option<String>,
        cuts: Vec<CutRow>,
        at: &str,
    ) -> StoreResult<(CarriedCut, CarriedReceipt)> {
        let mut steps = Vec::with_capacity(cuts.len());
        let mut reach = BTreeMap::new();
        let mut provenance = CarriedProvenance::default();
        for cut in &cuts {
            let manifest = self.load_manifest(Some(&cut.manifest_hash))?;
            for id in manifest.values() {
                reach.insert(id.clone(), id.clone());
            }
            steps.push(manifest);
            provenance.host_cut_ids.push(cut.cut_id.clone());
            provenance
                .change_ids
                .push(self.change_of(Some(&cut.cut_id))?);
        }
        // `reach` maps every id any step references to itself, so the bundle
        // collector walks each id (and each chunk) once.
        let blobs = crate::bundle::collect_blobs_delta(&reach, &self.content, &BTreeSet::new())?;
        let mut file_digests = BTreeMap::new();
        for id in reach.values() {
            // Erased and absent content both read as nothing: either way a
            // check on the far side could not run on it.
            let Some(bytes) = self.content.get(id)? else {
                return refuse(format!(
                    "`{id}` is not held here; a check cannot run on content that is gone"
                ));
            };
            file_digests.insert(id.clone(), sha256_hex(&bytes));
        }
        let header = CarriedHeader {
            format: CARRIED_CUT_FORMAT.to_owned(),
            kind,
            base,
            steps,
            file_digests,
        };
        let digest = header.digest()?;
        let canonical = header.canonical_bytes()?;
        let record_id = self.content.put(&canonical)?;
        // The local content id is shorter than the carriage digest. A store
        // that already holds different bytes under that id must not publish a
        // sent registry row that points at somebody else's header.
        if self.content.get(&record_id)?.as_deref() != Some(canonical.as_slice()) {
            return refuse("stored header differs from the carriage");
        }
        let step_manifest_hashes: Vec<String> =
            cuts.iter().map(|cut| cut.manifest_hash.clone()).collect();
        // The header is unrooted until its registry row commits, so the row is
        // published under the collector's exclusion with the header proven
        // still present.
        let mut retained = vec![record_id.clone()];
        retained.extend(step_manifest_hashes.iter().cloned());
        let receipt = self.register(
            CarriedCutRow {
                digest: digest.clone(),
                record_id,
                kind: kind.wire_name().to_owned(),
                direction: CarriageDirection::Sent,
                step_manifest_hashes,
                recorded_at: at.to_owned(),
            },
            kind,
            &retained,
        )?;
        Ok((
            CarriedCut {
                digest,
                header,
                provenance,
                blobs,
            },
            receipt.receipt().clone(),
        ))
    }

    /// The peer's door: record a carriage the Home supplied, by content. A cut
    /// or a prefix is accepted here; a returned peer line is not, because a
    /// peer has no use for one and a Home has its own door for it.
    pub fn record_carried_cut(
        &mut self,
        carried: &CarriedCut,
        at: &str,
    ) -> StoreResult<CarriageOutcome> {
        if carried.header.kind == CarriedKind::PeerLine {
            return refuse("a peer line is received by its Home, not recorded on a peer");
        }
        self.record_carriage(carried, at, &[])
    }

    /// The Home's door for a line a peer returns. Its base must be a carriage
    /// this Home sent, and the line is recorded by content as a candidate. No
    /// ref moves; admission is the review store's and the gate's, against the
    /// recorded candidate.
    pub fn receive_peer_line(
        &mut self,
        carried: &CarriedCut,
        at: &str,
    ) -> StoreResult<CarriageOutcome> {
        if carried.header.kind != CarriedKind::PeerLine {
            return refuse("only a peer line returns to a Home");
        }
        carried.header.check_shape()?;
        let base = carried
            .header
            .base
            .as_deref()
            .expect("checked: a peer line names its base");
        let (base_row, base_header) = self.recorded_carriage(base)?;
        if base_row.direction != CarriageDirection::Sent {
            return refuse("a peer line's base is a carriage this Home sent");
        }
        // A returned line can remove a file from its first step, so the line
        // bundle alone cannot establish that the Home still holds the base it
        // supplied. The review/gate must be able to read that exact base.
        self.verified_carried_steps(base)?;
        // Hold the sent base under the same content exclusion that publishes
        // the returned line. A competing erasure after the read above must
        // refuse the line's registry row, including when its first step has
        // removed a file that only the base references.
        let mut base_ids = vec![base_row.record_id];
        base_ids.extend(base_row.step_manifest_hashes);
        base_ids.extend(base_header.file_digests.into_keys());
        self.record_carriage(carried, at, &base_ids)
    }

    /// A carriage this store registered, with its header read back from
    /// content and checked against the digest it is registered under.
    pub fn recorded_carriage(&self, digest: &str) -> StoreResult<(CarriedCutRow, CarriedHeader)> {
        let Some(row) = self.branches.carriage(digest)? else {
            return refuse(format!(
                "carriage `{digest}` was not recorded by this store"
            ));
        };
        let Some(bytes) = self.content.get(&row.record_id)? else {
            return refuse(format!("carriage `{digest}` has lost its header"));
        };
        if sha256_hex(&bytes) != digest {
            return refuse(format!(
                "record `{}` is not the carriage `{digest}`",
                row.record_id
            ));
        }
        let header: CarriedHeader = serde_json::from_slice(&bytes)?;
        header.check_shape()?;
        if header.canonical_bytes()? != bytes {
            return refuse(format!("carriage `{digest}` has a noncanonical header"));
        }
        if row.kind != header.kind.wire_name() {
            return refuse(format!(
                "carriage `{digest}` has a mismatched registry kind"
            ));
        }
        if row.step_manifest_hashes.len() != header.steps.len() {
            return refuse(format!(
                "carriage `{digest}` has an incomplete step registry"
            ));
        }
        for (step, hash) in header.steps.iter().zip(&row.step_manifest_hashes) {
            if self.load_manifest(Some(hash))? != *step {
                return refuse(format!(
                    "carriage `{digest}` has a mismatched retained step"
                ));
            }
        }
        Ok((row, header))
    }

    /// All steps of a recorded carriage, with every referenced file checked
    /// against the full digest it carried. Retention prevents collection, but
    /// explicit erasure can remove a body after registration. A prefix is
    /// usable for checks only while its earlier steps remain available too.
    pub fn verified_carried_steps(
        &self,
        digest: &str,
    ) -> StoreResult<Vec<BTreeMap<String, String>>> {
        let (_, header) = self.recorded_carriage(digest)?;
        for (id, expected) in &header.file_digests {
            let Some(bytes) = self.content.get(id)? else {
                return refuse(format!("carried content `{id}` is unavailable"));
            };
            if &sha256_hex(&bytes) != expected {
                return refuse(format!("carried content `{id}` differs from the carriage"));
            }
        }
        Ok(header.steps)
    }

    /// A recorded carriage's last step, as files. Read-only and verified
    /// together with the whole prefix it belongs to.
    pub fn carried_head_manifest(&self, digest: &str) -> StoreResult<BTreeMap<String, String>> {
        Ok(self
            .verified_carried_steps(digest)?
            .pop()
            .expect("checked: a carriage has a step"))
    }

    /// Publish the registry row under the content authority's retention
    /// fence: every id in `retained` is proven present inside the collector's
    /// exclusion, and the row commits there. Without it a collector running on
    /// another connection between the content writes and the row could reclaim
    /// unrooted content, and the row would then name a header that is gone.
    fn register(
        &mut self,
        row: CarriedCutRow,
        kind: CarriedKind,
        retained: &[String],
    ) -> StoreResult<CarriageOutcome> {
        let branches = &mut self.branches;
        let outcome = self
            .content
            .publish_retained(retained, || branches.record_carriage(&row))?;
        Ok(match outcome {
            RecordCarriageOutcome::Recorded => CarriageOutcome::Recorded(receipt_of(&row, kind)),
            RecordCarriageOutcome::AlreadyRecorded(existing) => {
                let (checked, _) = self.recorded_carriage(&existing.digest)?;
                self.verified_carried_steps(&existing.digest)?;
                already_recorded(checked, row.direction, kind)?
            }
        })
    }

    fn record_carriage(
        &mut self,
        carried: &CarriedCut,
        at: &str,
        dependent_ids: &[String],
    ) -> StoreResult<CarriageOutcome> {
        let header = &carried.header;
        header.check_shape()?;
        let canonical = header.canonical_bytes()?;
        if sha256_hex(&canonical) != carried.digest {
            return refuse("its header does not hash to the digest it declares");
        }
        let verified = verify_blobs(header, &carried.blobs)?;
        if self.branches.carriage(&carried.digest)?.is_some() {
            // A retained row alone is not proof that its file bodies remain
            // available after explicit erasure. Do not issue a fresh receipt
            // for a carriage the peer can no longer use.
            let (existing, _) = self.recorded_carriage(&carried.digest)?;
            self.verified_carried_steps(&carried.digest)?;
            return already_recorded(existing, CarriageDirection::Received, header.kind);
        }
        let carried_ids = verified
            .plain
            .iter()
            .map(|(id, _)| id)
            .chain(verified.roots.iter().map(|(id, _, _)| id));
        for id in carried_ids {
            if matches!(
                self.content.status(id)?,
                crate::content::BlobStatus::Erased { .. }
            ) {
                return refuse(format!(
                    "`{id}` has been erased here; refusing resurrection"
                ));
            }
        }
        // Every check above wrote nothing. From here the content writes are
        // each idempotent, and the registry row goes last, published under the
        // retention fence with every id written here proven still present: a
        // crash between them leaves only unreferenced content, which the
        // collector may reclaim, and a collector that ran between them makes
        // the publication refuse rather than register what it took.
        let mut retained = Vec::new();
        for (id, bytes) in &verified.plain {
            self.content.put_unerased(bytes)?;
            retained.push(id.clone());
        }
        for (id, chunks, byte_len) in &verified.roots {
            self.content.put_chunk_root(id, chunks, *byte_len)?;
            retained.push(id.clone());
        }
        // `put` may keep an existing row under the store's shorter content id.
        // Verify what this authority now reads, not only the wire bytes checked
        // above, before a durable registry row claims to retain the carriage.
        for (id, expected) in &header.file_digests {
            let Some(bytes) = self.content.get(id)? else {
                return refuse(format!("stored content `{id}` is unavailable"));
            };
            if sha256_hex(&bytes) != *expected {
                return refuse(format!("stored content `{id}` differs from the carriage"));
            }
        }
        let prepared = crate::content::publication::PreparedBlobs::new(&self.content);
        let mut step_manifest_hashes = Vec::with_capacity(header.steps.len());
        for step in &header.steps {
            step_manifest_hashes.push(crate::manifest_tree::build(&prepared, step)?);
        }
        retained.extend(prepared.ids());
        retained.extend(step_manifest_hashes.iter().cloned());
        retained.extend_from_slice(dependent_ids);
        let record_id = self.content.put(&canonical)?;
        retained.push(record_id.clone());
        self.register(
            CarriedCutRow {
                digest: carried.digest.clone(),
                record_id,
                kind: header.kind.wire_name().to_owned(),
                direction: CarriageDirection::Received,
                step_manifest_hashes,
                recorded_at: at.to_owned(),
            },
            header.kind,
            &retained,
        )
    }
}

#[cfg(all(test, feature = "native"))]
mod tests;
