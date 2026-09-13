//! Read-only provenance discovery for one exact file version. A storage write
//! and its opaque evidence reference do not establish product admission.
use super::WorkspaceVcs;
use crate::branches::{write_evidence::WriteEvidenceRef, Branches};
use crate::content::ContentBlobs;
use crate::{StoreError, StoreResult};
use std::num::NonZeroUsize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileVersionSource {
    Absent,
    Write {
        cut_id: String,
        evidence: Option<WriteEvidenceRef>,
    },
    /// No original labeled write can be established through this operation.
    Opaque {
        cut_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedFileVersion {
    pub cut_id: String,
    pub path: String,
    /// Metadata only: this does not prove the body is available or readable.
    pub content_hash: Option<String>,
    pub source: FileVersionSource,
}

impl<B: Branches, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// A retained root is required even when the selected path is absent.
    pub(super) fn retained_manifest_entry(
        &self,
        hash: &str,
        path: &str,
    ) -> StoreResult<Option<String>> {
        let body = self
            .content
            .get_text(hash)?
            .text()
            .ok_or_else(|| StoreError::Conflict("retained manifest is unavailable".into()))?;
        crate::content::verify_body(hash, body.as_bytes(), "retained file manifest")?;
        if crate::manifest_tree::is_node(&body) {
            crate::manifest_tree::get(&self.content, hash, path)
        } else {
            let manifest: std::collections::BTreeMap<String, String> = serde_json::from_str(&body)?;
            Ok(manifest.get(path).cloned())
        }
    }

    /// Caller authorizes the selected path before discovery, then resolves the
    /// original label and current clearance before loading any file body.
    /// A bound or missing history is an error, never an empty file or a label.
    pub fn file_version_origin(
        &self,
        cut_id: &str,
        path: &str,
        hops: NonZeroUsize,
    ) -> StoreResult<RecordedFileVersion> {
        let unavailable = || StoreError::Conflict("file version history is unavailable".into());
        let mut cut = self.branches.get_cut(cut_id)?.ok_or_else(unavailable)?;
        let hash = self.retained_manifest_entry(&cut.manifest_hash, path)?;
        let observed = |source| RecordedFileVersion {
            cut_id: cut_id.into(),
            path: path.into(),
            content_hash: hash.clone(),
            source,
        };
        if hash.is_none() {
            return Ok(observed(FileVersionSource::Absent));
        }
        for _ in 0..hops.get() {
            let Some(written_path) = cut
                .origin
                .as_deref()
                .and_then(|origin| origin.strip_prefix("write:"))
            else {
                return Ok(observed(FileVersionSource::Opaque { cut_id: cut.cut_id }));
            };
            if written_path == path {
                let evidence = self.branches.write_evidence(&cut.cut_id)?;
                return Ok(observed(FileVersionSource::Write {
                    cut_id: cut.cut_id,
                    evidence,
                }));
            }
            let Some(parent_id) = cut.parent_cut_id.as_deref() else {
                return Ok(observed(FileVersionSource::Opaque { cut_id: cut.cut_id }));
            };
            let parent = self.branches.get_cut(parent_id)?.ok_or_else(unavailable)?;
            if self.retained_manifest_entry(&parent.manifest_hash, path)? != hash {
                return Ok(observed(FileVersionSource::Opaque { cut_id: cut.cut_id }));
            }
            cut = parent;
        }
        Err(StoreError::Conflict(
            "file version provenance exceeds the observation budget".into(),
        ))
    }
}

pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
