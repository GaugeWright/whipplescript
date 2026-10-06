//! Native WhippleScript revision references for reviewed contributions.
//!
//! A review revision snapshots identities from the VCS authority. It owns no
//! source unit, cut pin or ref transition. DR-0130's gate must recheck these
//! facts against the current base before admission.

use std::collections::BTreeSet;

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::branches::flowing_admission::FlowingAdmissions;
use crate::branches::flowing_fence::{FlowingFence, FlowingSourceKind};
use crate::branches::flowing_sources::FlowingSources;
use crate::branches::{BranchStatus, Branches};
use crate::content::ContentBlobs;
use crate::source_review::{ReviewError, ReviewResult, ReviewStore, SourceKind};
use crate::vcs::{
    FlowingBranchLineageOutcome, NativeCandidateOutcome, VerifiedNativeCandidate, WorkspaceVcs,
};

pub use crate::source_review_types::{NativeRevision, NativeUnitRef};

#[derive(Clone, Copy, Debug)]
pub struct NativeUpload<'a> {
    pub contribution_id: &'a str,
    pub upload_id: &'a str,
    pub actor: &'a str,
    pub source_branch_id: &'a str,
    pub source_cut_id: &'a str,
    pub unit_ids: &'a [&'a str],
}

#[derive(Clone, Copy, Debug)]
pub struct NativeCandidateRequest<'a> {
    pub contribution_id: &'a str,
    pub sequence: i64,
    pub expected_trunk_cut_id: Option<&'a str>,
    pub candidate_cut_id: &'a str,
    pub actor: &'a str,
    pub recorded_at: &'a str,
}

fn checked_named_upload_retry(
    existing: NativeRevision,
    actor: &str,
    source_branch_id: &str,
    source_cut_id: &str,
    unit_ids: &[&str],
    exact_units: Option<&[NativeUnitRef]>,
) -> ReviewResult<NativeRevision> {
    if existing.actor == actor
        && existing.source_branch_id == source_branch_id
        && existing.source_cut_id == source_cut_id
        && existing
            .units
            .iter()
            .map(|unit| unit.unit_id.as_str())
            .eq(unit_ids.iter().copied())
        && exact_units.is_none_or(|units| existing.units == units)
    {
        Ok(existing)
    } else {
        Err(ReviewError::Conflict(
            "upload id already names another revision".into(),
        ))
    }
}

impl ReviewStore {
    /// Construct a candidate from a persisted revision and the current exact
    /// trunk base. The VCS proves complete source-unit coverage and records
    /// the immutable cut; this review store owns neither cut nor unit state.
    pub fn prepare_native_candidate<
        B: Branches + FlowingSources + FlowingAdmissions,
        C: ContentBlobs,
    >(
        &self,
        vcs: &mut WorkspaceVcs<B, C>,
        request: NativeCandidateRequest<'_>,
    ) -> ReviewResult<NativeCandidateOutcome> {
        let contribution = self.contribution(request.contribution_id)?;
        if contribution.target_scope != crate::branches::MAINLINE_BRANCH_ID {
            return Err(ReviewError::Invalid(
                "native candidate needs the trunk target".into(),
            ));
        }
        if !contribution.predecessors.is_empty() {
            return Err(ReviewError::Invalid(
                "review predecessors need admission receipts before candidate construction".into(),
            ));
        }
        let revision = self.native_revision(request.contribution_id, request.sequence)?;
        let branch_source = vcs
            .branch_store()
            .flowing_source(&revision.source_branch_id)?
            .is_some_and(|source| source.kind == FlowingSourceKind::Branch);
        Ok(if branch_source {
            vcs.prepare_named_branch_candidate(
                &revision,
                request.expected_trunk_cut_id,
                request.candidate_cut_id,
                request.actor,
                request.recorded_at,
            )?
        } else {
            vcs.prepare_native_review_candidate(
                &revision,
                request.expected_trunk_cut_id,
                request.candidate_cut_id,
                request.actor,
                request.recorded_at,
            )?
        })
    }

    /// Verify the retained candidate against this authority's original
    /// immutable review revision. Reading creates no candidate or receipt.
    pub fn verify_retained_native_candidate<
        B: Branches + FlowingSources + FlowingAdmissions + FlowingFence,
        C: ContentBlobs,
    >(
        &self,
        vcs: &WorkspaceVcs<B, C>,
        witness_digest: &str,
        attempt_id: &str,
    ) -> ReviewResult<VerifiedNativeCandidate> {
        let retained = vcs.capture_gate_subject(witness_digest, attempt_id)?;
        let witness = retained.witness();
        let contribution = self.contribution(&witness.contribution_id)?;
        if contribution.source_kind != SourceKind::Native
            || contribution.target_scope != crate::branches::MAINLINE_BRANCH_ID
            || !contribution.predecessors.is_empty()
        {
            return Err(ReviewError::Invalid(
                "native candidate needs the exact trunk contribution and predecessor receipts"
                    .into(),
            ));
        }
        let revision = self.native_revision(&witness.contribution_id, witness.revision_sequence)?;
        Ok(vcs.verify_retained_native_candidate(&revision, witness_digest, attempt_id)?)
    }

    /// The caller authenticates `actor`. This checks the VCS's retained unit
    /// facts and immutable cut before recording a reference. A later tail can
    /// move the source head without changing this revision. This is not a
    /// dependency-closure or gate certificate.
    pub fn upload_native_revision<S: Branches + FlowingSources>(
        &mut self,
        source: &S,
        request: NativeUpload<'_>,
    ) -> ReviewResult<NativeRevision> {
        let NativeUpload {
            contribution_id,
            upload_id,
            actor,
            source_branch_id,
            source_cut_id,
            unit_ids,
        } = request;
        if upload_id.is_empty()
            || upload_id.len() > 64
            || !upload_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ReviewError::Invalid("invalid upload id".into()));
        }
        if actor.trim().is_empty() || unit_ids.is_empty() {
            return Err(ReviewError::Invalid(
                "actor and selected units are required".into(),
            ));
        }
        let contribution = self.contribution(contribution_id)?;
        if contribution.source_kind != SourceKind::Native {
            return Err(ReviewError::Invalid(
                "native revision needs a native contribution".into(),
            ));
        }
        if contribution.author != actor {
            return Err(ReviewError::Invalid("only the author may upload".into()));
        }
        if let Some(existing) = self.native_revision_by_upload(contribution_id, upload_id)? {
            if existing.actor == actor
                && existing.source_branch_id == source_branch_id
                && existing.source_cut_id == source_cut_id
                && existing
                    .units
                    .iter()
                    .map(|unit| unit.unit_id.as_str())
                    .collect::<Vec<_>>()
                    == unit_ids
            {
                return Ok(existing);
            }
            return Err(ReviewError::Conflict(
                "upload id already names another revision".into(),
            ));
        }

        let branch = source
            .get_branch(source_branch_id)?
            .ok_or_else(|| ReviewError::Missing(format!("source branch {source_branch_id}")))?;
        let target = source
            .get_branch(&contribution.target_scope)?
            .ok_or_else(|| {
                ReviewError::Missing(format!("target branch {}", contribution.target_scope))
            })?;
        if branch.status != BranchStatus::Active
            || target.status != BranchStatus::Active
            || branch.parent_branch_id.as_deref() != Some(contribution.target_scope.as_str())
        {
            return Err(ReviewError::Invalid(
                "source must be an active child of the target".into(),
            ));
        }
        let fence = source
            .flowing_source(source_branch_id)?
            .ok_or_else(|| ReviewError::Missing(format!("flowing source {source_branch_id}")))?;
        if fence.kind != FlowingSourceKind::Twig
            || !fence.admission_enabled
            || fence.revision.is_some()
        {
            return Err(ReviewError::Invalid(
                "source needs an eligible settled twig".into(),
            ));
        }
        let cut = source
            .get_cut(source_cut_id)?
            .ok_or_else(|| ReviewError::Missing(format!("source cut {source_cut_id}")))?;
        if cut.branch_id != source_branch_id {
            return Err(ReviewError::Invalid(
                "selected cut belongs to another line".into(),
            ));
        }
        let head = branch
            .head_cut_id
            .as_deref()
            .ok_or_else(|| ReviewError::Invalid("source has no head cut".into()))?;
        let head_ancestors = ancestors(source, head)?;
        if !head_ancestors.contains(source_cut_id) {
            return Err(ReviewError::Invalid(
                "selected cut is not retained in source head".into(),
            ));
        }
        let selected_ancestors = ancestors(source, source_cut_id)?;

        let mut seen = BTreeSet::new();
        let mut units = Vec::with_capacity(unit_ids.len());
        let mut selected_cut_has_unit = false;
        for unit_id in unit_ids {
            if unit_id.is_empty() || !seen.insert(*unit_id) {
                return Err(ReviewError::Invalid(
                    "selected unit ids must be distinct".into(),
                ));
            }
            let declaration = source
                .contribution_declaration(unit_id)?
                .ok_or_else(|| ReviewError::Missing(format!("source unit {unit_id}")))?;
            if declaration.source_branch_id != source_branch_id
                || declaration.principal != actor
                || !selected_ancestors.contains(&declaration.source_cut_id)
            {
                return Err(ReviewError::Invalid(
                    "unit is outside the selected source prefix".into(),
                ));
            }
            if source.contribution_handoff(unit_id)?.is_some() {
                return Err(ReviewError::Invalid(
                    "handoff lineage is not yet supported".into(),
                ));
            }
            let unit_cut = source.get_cut(&declaration.source_cut_id)?.ok_or_else(|| {
                ReviewError::Missing(format!("unit cut {}", declaration.source_cut_id))
            })?;
            if unit_cut.branch_id != source_branch_id
                || unit_cut.manifest_hash != declaration.source_manifest_hash
            {
                return Err(ReviewError::Corrupt(
                    "unit declaration disagrees with its recorded cut".into(),
                ));
            }
            let pin = source
                .private_cut_pin(&declaration.pin_id)?
                .ok_or_else(|| {
                    ReviewError::Missing(format!("source pin {}", declaration.pin_id))
                })?;
            if pin.released_at.is_some()
                || pin.twig_branch_id != source_branch_id
                || pin.cut_id != declaration.source_cut_id
                || pin.manifest_hash != declaration.source_manifest_hash
            {
                return Err(ReviewError::Invalid(
                    "source unit pin no longer retains its cut".into(),
                ));
            }
            let basis = source
                .contribution_basis(unit_id)?
                .ok_or_else(|| ReviewError::Missing(format!("source unit basis {unit_id}")))?;
            selected_cut_has_unit |= declaration.source_cut_id == source_cut_id;
            units.push(NativeUnitRef {
                unit_id: (*unit_id).into(),
                source_cut_id: declaration.source_cut_id,
                pin_id: declaration.pin_id,
                basis_digest: basis.basis_digest,
                principal: declaration.principal,
                intent: declaration.intent,
            });
        }
        if !selected_cut_has_unit {
            return Err(ReviewError::Invalid(
                "selected cut must be a selected unit boundary".into(),
            ));
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = revision_by_upload(&tx, contribution_id, upload_id)? {
            if existing.actor == actor
                && existing.source_branch_id == source_branch_id
                && existing.source_cut_id == source_cut_id
                && existing.units == units
            {
                return Ok(existing);
            }
            return Err(ReviewError::Conflict(
                "upload id already names another revision".into(),
            ));
        }
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM native_revisions WHERE contribution_id=?1",
            [contribution_id],
            |row| row.get(0),
        )?;
        let revision = NativeRevision {
            contribution_id: contribution_id.into(),
            sequence,
            upload_id: upload_id.into(),
            actor: actor.into(),
            source_branch_id: source_branch_id.into(),
            source_incarnation_id: fence.incarnation_id,
            source_cut_id: source_cut_id.into(),
            source_manifest_hash: cut.manifest_hash,
            units,
        };
        tx.execute(
            "INSERT INTO native_revisions (contribution_id, sequence, upload_id, revision_json) VALUES (?1, ?2, ?3, ?4)",
            params![contribution_id, sequence, upload_id, serde_json::to_string(&revision).map_err(|err| ReviewError::Corrupt(err.to_string()))?],
        )?;
        tx.commit()?;
        Ok(revision)
    }

    /// Snapshot a complete, content-verified simple handoff prefix from a
    /// named branch. The review revision is a durable proposal; candidate
    /// construction repeats the lineage and read-basis proof at its exact
    /// trunk base, and ref admission remains separately fenced.
    pub fn upload_named_branch_revision<
        B: Branches + FlowingSources + FlowingAdmissions,
        C: ContentBlobs,
    >(
        &mut self,
        vcs: &WorkspaceVcs<B, C>,
        request: NativeUpload<'_>,
    ) -> ReviewResult<NativeRevision> {
        let NativeUpload {
            contribution_id,
            upload_id,
            actor,
            source_branch_id,
            source_cut_id,
            unit_ids,
        } = request;
        if upload_id.is_empty()
            || upload_id.len() > 64
            || !upload_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || actor.trim().is_empty()
            || unit_ids.is_empty()
        {
            return Err(ReviewError::Invalid(
                "upload id, actor and selected units are required".into(),
            ));
        }
        let contribution = self.contribution(contribution_id)?;
        if contribution.source_kind != SourceKind::Native
            || contribution.target_scope != crate::branches::MAINLINE_BRANCH_ID
            || contribution.author != actor
        {
            return Err(ReviewError::Invalid(
                "named branch upload needs its author's native trunk contribution".into(),
            ));
        }
        if let Some(existing) = self.native_revision_by_upload(contribution_id, upload_id)? {
            return checked_named_upload_retry(
                existing,
                actor,
                source_branch_id,
                source_cut_id,
                unit_ids,
                None,
            );
        }
        let branch = vcs
            .branch_store()
            .get_branch(source_branch_id)?
            .ok_or_else(|| ReviewError::Missing(format!("source branch {source_branch_id}")))?;
        let fence = vcs
            .branch_store()
            .flowing_source(source_branch_id)?
            .ok_or_else(|| ReviewError::Missing(format!("flowing source {source_branch_id}")))?;
        if branch.status != BranchStatus::Active
            || branch.name.is_none()
            || branch.parent_branch_id.as_deref() != Some(crate::branches::MAINLINE_BRANCH_ID)
            || fence.kind != FlowingSourceKind::Branch
            || !fence.admission_enabled
            || fence.revision.is_some()
            || fence.owner != actor
        {
            return Err(ReviewError::Invalid(
                "source needs an eligible named branch owned by the uploader".into(),
            ));
        }
        let FlowingBranchLineageOutcome::Verified(lineage) =
            vcs.inspect_flowing_branch_lineage(source_branch_id)?
        else {
            return Err(ReviewError::Invalid(
                "source branch handoff lineage is incomplete".into(),
            ));
        };
        let prefix = lineage.prefix_through(source_cut_id).ok_or_else(|| {
            ReviewError::Invalid("selected cut is not a handoff receipt boundary".into())
        })?;
        if prefix
            .selected_handoffs()
            .iter()
            .map(|receipt| receipt.unit_id.as_str())
            .ne(unit_ids.iter().copied())
        {
            return Err(ReviewError::Invalid(
                "selected units must be the complete ordered handoff prefix".into(),
            ));
        }
        let units = prefix
            .selected_sources()
            .iter()
            .map(|source| NativeUnitRef {
                unit_id: source.unit_id.clone(),
                source_cut_id: source.source_cut_id.clone(),
                pin_id: source.pin_id.clone(),
                basis_digest: source.basis_digest.clone(),
                principal: source.principal.clone(),
                intent: source.intent.clone(),
            })
            .collect::<Vec<_>>();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = revision_by_upload(&tx, contribution_id, upload_id)? {
            return checked_named_upload_retry(
                existing,
                actor,
                source_branch_id,
                source_cut_id,
                unit_ids,
                Some(&units),
            );
        }
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM native_revisions WHERE contribution_id=?1",
            [contribution_id],
            |row| row.get(0),
        )?;
        let revision = NativeRevision {
            contribution_id: contribution_id.into(),
            sequence,
            upload_id: upload_id.into(),
            actor: actor.into(),
            source_branch_id: source_branch_id.into(),
            source_incarnation_id: fence.incarnation_id,
            source_cut_id: source_cut_id.into(),
            source_manifest_hash: prefix.selected_manifest_hash().into(),
            units,
        };
        tx.execute(
            "INSERT INTO native_revisions (contribution_id, sequence, upload_id, revision_json) VALUES (?1, ?2, ?3, ?4)",
            params![contribution_id, sequence, upload_id, serde_json::to_string(&revision).map_err(|err| ReviewError::Corrupt(err.to_string()))?],
        )?;
        tx.commit()?;
        Ok(revision)
    }

    pub fn native_revision(
        &self,
        contribution_id: &str,
        sequence: i64,
    ) -> ReviewResult<NativeRevision> {
        let value: Option<(String, String)> = self.connection.query_row(
            "SELECT upload_id, revision_json FROM native_revisions WHERE contribution_id=?1 AND sequence=?2",
            params![contribution_id, sequence],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let (upload_id, json) = value.ok_or_else(|| {
            ReviewError::Missing(format!("native revision {contribution_id}/{sequence}"))
        })?;
        decode_revision(&json, contribution_id, sequence, &upload_id)
    }

    fn native_revision_by_upload(
        &self,
        contribution_id: &str,
        upload_id: &str,
    ) -> ReviewResult<Option<NativeRevision>> {
        revision_by_upload(&self.connection, contribution_id, upload_id)
    }
}

fn ancestors<S: Branches>(source: &S, cut_id: &str) -> ReviewResult<BTreeSet<String>> {
    let mut seen = BTreeSet::new();
    let mut next = Some(cut_id.to_owned());
    while let Some(id) = next {
        if !seen.insert(id.clone()) {
            return Err(ReviewError::Corrupt("cyclic source cut lineage".into()));
        }
        let cut = source
            .get_cut(&id)?
            .ok_or_else(|| ReviewError::Missing(format!("ancestor cut {id}")))?;
        next = cut.parent_cut_id;
    }
    Ok(seen)
}

fn revision_by_upload(
    connection: &rusqlite::Connection,
    contribution_id: &str,
    upload_id: &str,
) -> ReviewResult<Option<NativeRevision>> {
    let row: Option<(i64, String)> = connection.query_row(
        "SELECT sequence, revision_json FROM native_revisions WHERE contribution_id=?1 AND upload_id=?2",
        params![contribution_id, upload_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    row.map(|(sequence, json)| decode_revision(&json, contribution_id, sequence, upload_id))
        .transpose()
}

fn decode_revision(
    json: &str,
    contribution_id: &str,
    sequence: i64,
    upload_id: &str,
) -> ReviewResult<NativeRevision> {
    let revision: NativeRevision =
        serde_json::from_str(json).map_err(|err| ReviewError::Corrupt(err.to_string()))?;
    if revision.contribution_id != contribution_id
        || revision.sequence != sequence
        || revision.upload_id != upload_id
    {
        return Err(ReviewError::Corrupt(
            "native revision identity disagrees with its row".into(),
        ));
    }
    Ok(revision)
}
