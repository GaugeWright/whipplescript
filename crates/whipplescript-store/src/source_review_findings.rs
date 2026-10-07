//! Content-anchored findings, approvals and exact read/diff APIs over native
//! review revisions (WhippleScript DR-0141, `spec/source-review.md`).
//!
//! Discussion attaches to the contribution and names the revision and content
//! anchor it concerns. A finding is anchored to one path, the exact blob that
//! path held in its revision, and a line range of that blob. A later revision
//! keeps every finding; a finding is current only while the latest revision
//! still holds the identical blob at that path, and stale otherwise.
//!
//! An approval binds one whole revision. A later revision makes it stale even
//! when its content is equal, because a changed review revision is a distinct
//! subject and evidence reuse needs an explicit policy proof this store does
//! not supply. Stale approvals are refused rather than returned as current.
//!
//! Every read re-derives a revision's content from the VCS and checks it
//! against the revision's recorded cut and manifest, so a changed revision or
//! anchor row is refused rather than silently re-pointed. None of this is a
//! gate verdict, admission certificate or authentication of the actor; the
//! caller authenticates `actor`.

use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::branches::Branches;
use crate::content::{ContentBlobs, TextBlob};
use crate::diff::{diff_manifests, DiffEntry};
use crate::source_review::{ReviewError, ReviewResult, ReviewStore, SourceKind};
use crate::source_review_types::NativeRevision;
use crate::vcs::WorkspaceVcs;

/// A path, the exact blob it held in the revision, and a 1-based inclusive
/// line range of that blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentAnchor {
    pub path: String,
    pub blob_digest: String,
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub contribution_id: String,
    pub finding_id: String,
    pub sequence: i64,
    pub manifest_hash: String,
    pub actor: String,
    pub anchor: ContentAnchor,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub contribution_id: String,
    pub approval_id: String,
    pub sequence: i64,
    pub manifest_hash: String,
    pub actor: String,
}

/// Whether content-bound evidence still describes the latest revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceState {
    Current,
    Stale { latest_sequence: i64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingView {
    pub finding: Finding,
    pub state: EvidenceState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionFile {
    pub path: String,
    pub blob_digest: String,
    pub body: TextBlob,
}

#[derive(Clone, Copy, Debug)]
pub struct NewFinding<'a> {
    pub contribution_id: &'a str,
    pub finding_id: &'a str,
    pub sequence: i64,
    pub actor: &'a str,
    pub path: &'a str,
    pub blob_digest: &'a str,
    pub start_line: u32,
    pub end_line: u32,
    pub body: &'a str,
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl ReviewStore {
    /// The latest native revision of a contribution.
    pub fn latest_native_sequence(&self, contribution_id: &str) -> ReviewResult<i64> {
        let latest: Option<i64> = self.connection.query_row(
            "SELECT MAX(sequence) FROM native_revisions WHERE contribution_id=?1",
            [contribution_id],
            |row| row.get(0),
        )?;
        latest.ok_or_else(|| ReviewError::Missing(format!("revisions of {contribution_id}")))
    }

    /// One file exactly as the revision recorded it.
    pub fn revision_file<B: Branches, C: ContentBlobs>(
        &self,
        vcs: &WorkspaceVcs<B, C>,
        contribution_id: &str,
        sequence: i64,
        path: &str,
    ) -> ReviewResult<RevisionFile> {
        let (_, manifest) = self.verified_revision_manifest(vcs, contribution_id, sequence)?;
        let blob_digest = manifest.get(path).cloned().ok_or_else(|| {
            ReviewError::Missing(format!("{path} in revision {contribution_id}/{sequence}"))
        })?;
        let body = vcs.content_store().get_text(&blob_digest)?;
        Ok(RevisionFile {
            path: path.into(),
            blob_digest,
            body,
        })
    }

    /// The exact per-path diff between two revisions of one contribution.
    pub fn diff_revisions<B: Branches, C: ContentBlobs>(
        &self,
        vcs: &WorkspaceVcs<B, C>,
        contribution_id: &str,
        base_sequence: i64,
        target_sequence: i64,
        context: usize,
    ) -> ReviewResult<Vec<DiffEntry>> {
        let (_, base) = self.verified_revision_manifest(vcs, contribution_id, base_sequence)?;
        let (_, target) = self.verified_revision_manifest(vcs, contribution_id, target_sequence)?;
        Ok(diff_manifests(
            &base,
            &target,
            vcs.content_store(),
            context,
        )?)
    }

    /// Record a finding anchored to content the named revision actually holds.
    /// Retrying the same finding id with the same content returns the record;
    /// reusing the id for anything else is refused.
    pub fn record_finding<B: Branches, C: ContentBlobs>(
        &mut self,
        vcs: &WorkspaceVcs<B, C>,
        request: NewFinding<'_>,
    ) -> ReviewResult<Finding> {
        let NewFinding {
            contribution_id,
            finding_id,
            sequence,
            actor,
            path,
            blob_digest,
            start_line,
            end_line,
            body,
        } = request;
        if !valid_token(finding_id) {
            return Err(ReviewError::Invalid("invalid finding id".into()));
        }
        if actor.trim().is_empty() || body.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "finding actor and body are required".into(),
            ));
        }
        let (revision, manifest) =
            self.verified_revision_manifest(vcs, contribution_id, sequence)?;
        if manifest.get(path).map(String::as_str) != Some(blob_digest) {
            return Err(ReviewError::Conflict(
                "finding anchor is not the revision's content at that path".into(),
            ));
        }
        let TextBlob::Text(text) = vcs.content_store().get_text(blob_digest)? else {
            return Err(ReviewError::Invalid(
                "a line anchor needs readable text content".into(),
            ));
        };
        let lines = text.lines().count();
        if start_line == 0 || end_line < start_line || end_line as usize > lines {
            return Err(ReviewError::Invalid(
                "finding line range is outside the anchored content".into(),
            ));
        }
        let finding = Finding {
            contribution_id: contribution_id.into(),
            finding_id: finding_id.into(),
            sequence,
            manifest_hash: revision.source_manifest_hash,
            actor: actor.into(),
            anchor: ContentAnchor {
                path: path.into(),
                blob_digest: blob_digest.into(),
                start_line,
                end_line,
            },
            body: body.into(),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = finding_row(&tx, contribution_id, finding_id)? {
            if existing == finding {
                return Ok(existing);
            }
            return Err(ReviewError::Conflict(
                "finding id already names another finding".into(),
            ));
        }
        tx.execute(
            "INSERT INTO review_findings
             (contribution_id, finding_id, sequence, manifest_hash, actor, path,
              blob_digest, start_line, end_line, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                finding.contribution_id,
                finding.finding_id,
                finding.sequence,
                finding.manifest_hash,
                finding.actor,
                finding.anchor.path,
                finding.anchor.blob_digest,
                finding.anchor.start_line,
                finding.anchor.end_line,
                finding.body,
            ],
        )?;
        tx.commit()?;
        Ok(finding)
    }

    /// Every finding on the contribution, each judged against the latest
    /// revision. Discussion is never dropped; stale findings are marked.
    pub fn findings<B: Branches, C: ContentBlobs>(
        &self,
        vcs: &WorkspaceVcs<B, C>,
        contribution_id: &str,
    ) -> ReviewResult<Vec<FindingView>> {
        let latest_sequence = self.latest_native_sequence(contribution_id)?;
        let (_, latest) = self.verified_revision_manifest(vcs, contribution_id, latest_sequence)?;
        let mut statement = self.connection.prepare(
            "SELECT contribution_id, finding_id, sequence, manifest_hash, actor, path,
                    blob_digest, start_line, end_line, body
             FROM review_findings WHERE contribution_id=?1 ORDER BY sequence, finding_id",
        )?;
        let findings = statement
            .query_map([contribution_id], read_finding)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut views = Vec::with_capacity(findings.len());
        for finding in findings {
            let (revision, manifest) =
                self.verified_revision_manifest(vcs, contribution_id, finding.sequence)?;
            if revision.source_manifest_hash != finding.manifest_hash
                || manifest.get(&finding.anchor.path) != Some(&finding.anchor.blob_digest)
            {
                return Err(ReviewError::Corrupt(format!(
                    "finding {} no longer matches its revision's content",
                    finding.finding_id
                )));
            }
            let state = if latest.get(&finding.anchor.path) == Some(&finding.anchor.blob_digest) {
                EvidenceState::Current
            } else {
                EvidenceState::Stale { latest_sequence }
            };
            views.push(FindingView { finding, state });
        }
        Ok(views)
    }

    /// Approve the latest revision. An approval of a superseded revision is
    /// refused; an identical retry returns the original record.
    pub fn record_approval(
        &mut self,
        contribution_id: &str,
        approval_id: &str,
        sequence: i64,
        actor: &str,
    ) -> ReviewResult<Approval> {
        if !valid_token(approval_id) {
            return Err(ReviewError::Invalid("invalid approval id".into()));
        }
        if actor.trim().is_empty() {
            return Err(ReviewError::Invalid("approval actor is required".into()));
        }
        let revision = self.native_review_revision(contribution_id, sequence)?;
        let approval = Approval {
            contribution_id: contribution_id.into(),
            approval_id: approval_id.into(),
            sequence,
            manifest_hash: revision.source_manifest_hash,
            actor: actor.into(),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = approval_row(&tx, contribution_id, approval_id)? {
            if existing == approval {
                return Ok(existing);
            }
            return Err(ReviewError::Conflict(
                "approval id already names another approval".into(),
            ));
        }
        let latest: i64 = tx.query_row(
            "SELECT MAX(sequence) FROM native_revisions WHERE contribution_id=?1",
            [contribution_id],
            |row| row.get(0),
        )?;
        if latest != sequence {
            return Err(ReviewError::Stale(format!(
                "revision {sequence} is superseded by revision {latest}"
            )));
        }
        tx.execute(
            "INSERT INTO review_approvals
             (contribution_id, approval_id, sequence, manifest_hash, actor)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                approval.contribution_id,
                approval.approval_id,
                approval.sequence,
                approval.manifest_hash,
                approval.actor,
            ],
        )?;
        tx.commit()?;
        Ok(approval)
    }

    /// The approvals that still bind `sequence`. Refuses when that revision is
    /// no longer the latest, so stale approvals cannot be read as current.
    pub fn current_approvals(
        &self,
        contribution_id: &str,
        sequence: i64,
    ) -> ReviewResult<Vec<Approval>> {
        let revision = self.native_review_revision(contribution_id, sequence)?;
        let latest = self.latest_native_sequence(contribution_id)?;
        if latest != sequence {
            return Err(ReviewError::Stale(format!(
                "approvals of revision {sequence} are stale at revision {latest}"
            )));
        }
        let mut statement = self.connection.prepare(
            "SELECT contribution_id, approval_id, sequence, manifest_hash, actor
             FROM review_approvals WHERE contribution_id=?1 AND sequence=?2
             ORDER BY approval_id",
        )?;
        let approvals = statement
            .query_map(params![contribution_id, sequence], read_approval)?
            .collect::<Result<Vec<_>, _>>()?;
        if approvals
            .iter()
            .any(|approval| approval.manifest_hash != revision.source_manifest_hash)
        {
            return Err(ReviewError::Corrupt(
                "approval no longer matches its revision's content".into(),
            ));
        }
        Ok(approvals)
    }

    fn native_review_revision(
        &self,
        contribution_id: &str,
        sequence: i64,
    ) -> ReviewResult<NativeRevision> {
        if self.contribution(contribution_id)?.source_kind != SourceKind::Native {
            return Err(ReviewError::Invalid(
                "content anchors need a native contribution".into(),
            ));
        }
        self.native_revision(contribution_id, sequence)
    }

    /// The revision and the manifest its recorded cut holds. A revision whose
    /// recorded cut is absent or holds other content is refused.
    fn verified_revision_manifest<B: Branches, C: ContentBlobs>(
        &self,
        vcs: &WorkspaceVcs<B, C>,
        contribution_id: &str,
        sequence: i64,
    ) -> ReviewResult<(NativeRevision, BTreeMap<String, String>)> {
        let revision = self.native_review_revision(contribution_id, sequence)?;
        let cut = vcs.branch_store().get_cut(&revision.source_cut_id)?;
        if cut.map(|cut| (cut.branch_id, cut.manifest_hash))
            != Some((
                revision.source_branch_id.clone(),
                revision.source_manifest_hash.clone(),
            ))
        {
            return Err(ReviewError::Corrupt(
                "revision disagrees with its recorded source cut".into(),
            ));
        }
        let manifest = vcs.manifest_by_hash(&revision.source_manifest_hash)?;
        Ok((revision, manifest))
    }
}

fn read_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    Ok(Finding {
        contribution_id: row.get(0)?,
        finding_id: row.get(1)?,
        sequence: row.get(2)?,
        manifest_hash: row.get(3)?,
        actor: row.get(4)?,
        anchor: ContentAnchor {
            path: row.get(5)?,
            blob_digest: row.get(6)?,
            start_line: row.get(7)?,
            end_line: row.get(8)?,
        },
        body: row.get(9)?,
    })
}

fn read_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<Approval> {
    Ok(Approval {
        contribution_id: row.get(0)?,
        approval_id: row.get(1)?,
        sequence: row.get(2)?,
        manifest_hash: row.get(3)?,
        actor: row.get(4)?,
    })
}

fn finding_row(
    connection: &rusqlite::Connection,
    contribution_id: &str,
    finding_id: &str,
) -> ReviewResult<Option<Finding>> {
    Ok(connection
        .query_row(
            "SELECT contribution_id, finding_id, sequence, manifest_hash, actor, path,
                    blob_digest, start_line, end_line, body
             FROM review_findings WHERE contribution_id=?1 AND finding_id=?2",
            params![contribution_id, finding_id],
            read_finding,
        )
        .optional()?)
}

fn approval_row(
    connection: &rusqlite::Connection,
    contribution_id: &str,
    approval_id: &str,
) -> ReviewResult<Option<Approval>> {
    Ok(connection
        .query_row(
            "SELECT contribution_id, approval_id, sequence, manifest_hash, actor
             FROM review_approvals WHERE contribution_id=?1 AND approval_id=?2",
            params![contribution_id, approval_id],
            read_approval,
        )
        .optional()?)
}
