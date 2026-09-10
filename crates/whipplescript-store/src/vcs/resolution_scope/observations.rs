use super::*;
use crate::branches::resolution_origin::ResolutionObservation;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPayloadUse {
    NotRead,
    Unavailable,
    NonText,
    Applied,
}

/// One lookup actually made during this candidate. The source receipt is an
/// evidence reference, never an authorization token or a fresh attribution.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionLookup {
    pub triple_key: String,
    pub observed: ResolutionObservation,
    pub payload_use: ResolutionPayloadUse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedSaveOutcome {
    pub outcome: SaveWithBaseOutcome,
    pub scope: ResolutionMemoryScope,
    pub observations: Vec<ResolutionLookup>,
}

pub(in crate::vcs) fn applied_ids(observations: &[ResolutionLookup]) -> Vec<String> {
    observations
        .iter()
        .filter_map(|lookup| match (&lookup.observed, lookup.payload_use) {
            (
                ResolutionObservation::Recorded { content_hash, .. },
                ResolutionPayloadUse::Applied,
            ) => Some(content_hash.clone()),
            _ => None,
        })
        .collect()
}

impl<B: Branches, C: ContentBlobs> WorkspaceVcs<B, C> {
    pub(in crate::vcs) fn observe_resolution_payload(
        &self,
        key: String,
        observations: &mut Vec<ResolutionLookup>,
    ) -> StoreResult<Option<String>> {
        let observed = self.branches.resolution_observation(&key)?;
        let (payload_use, text) = match &observed {
            ResolutionObservation::Recorded { content_hash, .. } => {
                match self.content.get(content_hash)? {
                    Some(bytes) => {
                        crate::content::verify_body(
                            content_hash,
                            &bytes,
                            "remembered resolution input",
                        )?;
                        match String::from_utf8(bytes) {
                            Ok(text) => (ResolutionPayloadUse::Applied, Some(text)),
                            Err(_) => (ResolutionPayloadUse::NonText, None),
                        }
                    }
                    None => (ResolutionPayloadUse::Unavailable, None),
                }
            }
            ResolutionObservation::Missing | ResolutionObservation::OriginUnavailable { .. } => {
                (ResolutionPayloadUse::NotRead, None)
            }
        };
        observations.push(ResolutionLookup {
            triple_key: key,
            observed,
            payload_use,
        });
        Ok(text)
    }
}
