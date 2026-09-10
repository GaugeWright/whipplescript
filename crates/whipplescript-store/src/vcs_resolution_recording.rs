//! A bound independent knowledge operation, not an execution or access grant.
//! The host records this descriptor with verified dispatch before target I/O.
use crate::branches::resolution_batch::{ResolutionMemoryBatch, ResolutionMemoryReceipt};
use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::text_merge::RegionResolution;
use crate::vcs::resolution_recording::prepare_batch;
use crate::vcs::resolution_scope::ResolutionMemoryScope;
use crate::vcs::WorkspaceVcs;
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};

pub const RESOLUTION_INPUT_PROTOCOL: &str = "whipplescript.resolution-recording-input.v1";
pub const RESOLUTION_BINDING_PROTOCOL: &str = "whipplescript.resolution-recording-binding.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "InputWire")]
pub struct ResolutionRecordingInput {
    protocol: String,
    resolutions: Vec<RegionResolution>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputWire {
    protocol: String,
    resolutions: Vec<RegionWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionWire {
    base_text: String,
    ours_text: String,
    theirs_text: String,
    resolution_text: String,
}
impl TryFrom<InputWire> for ResolutionRecordingInput {
    type Error = String;
    fn try_from(wire: InputWire) -> Result<Self, String> {
        if wire.protocol != RESOLUTION_INPUT_PROTOCOL || wire.resolutions.is_empty() {
            return Err("resolution input requires its protocol and nonempty resolutions".into());
        }
        Ok(Self {
            protocol: wire.protocol,
            resolutions: wire
                .resolutions
                .into_iter()
                .map(|entry| RegionResolution {
                    base_text: entry.base_text,
                    ours_text: entry.ours_text,
                    theirs_text: entry.theirs_text,
                    resolution_text: entry.resolution_text,
                })
                .collect(),
        })
    }
}
impl ResolutionRecordingInput {
    pub fn new(resolutions: Vec<RegionResolution>) -> StoreResult<Self> {
        let value =
            serde_json::json!({"protocol": RESOLUTION_INPUT_PROTOCOL, "resolutions": resolutions});
        Ok(serde_json::from_value(value)?)
    }
}

/// Immutable recovery coordinates. The original protected body is deliberately
/// absent; these keys are prepared once, not reconstructed during investigation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BindingWire")]
pub struct ResolutionRecordingBinding {
    protocol: String,
    input_hash: String,
    input_label: String,
    scope: ResolutionMemoryScope,
    batch: ResolutionMemoryBatch,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    protocol: String,
    input_hash: String,
    input_label: String,
    scope: ResolutionMemoryScope,
    batch: ResolutionMemoryBatch,
}
fn hash(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl TryFrom<BindingWire> for ResolutionRecordingBinding {
    type Error = String;
    fn try_from(wire: BindingWire) -> Result<Self, String> {
        if wire.protocol != RESOLUTION_BINDING_PROTOCOL
            || !hash(&wire.input_hash, 32)
            || wire.input_label.trim().is_empty()
            || wire.batch.validate().is_err()
            || wire.batch.entries.iter().any(|entry| {
                !entry
                    .triple_key
                    .strip_prefix("rks1|")
                    .is_some_and(|key| hash(key, 64))
                    || !hash(&entry.resolution, 32)
            })
        {
            return Err("resolution recording binding has invalid coordinates".into());
        }
        Ok(Self {
            protocol: wire.protocol,
            input_hash: wire.input_hash,
            input_label: wire.input_label,
            scope: wire.scope,
            batch: wire.batch,
        })
    }
}
impl ResolutionRecordingBinding {
    /// Pure preparation; input custody, scope authority and IFC remain the
    /// governed caller's obligations. Empty region texts are valid deletions.
    pub fn prepare(
        input_json: &str,
        input_label: &str,
        scope: ResolutionMemoryScope,
        operation_id: &str,
        actor: &str,
        intent: &str,
        recorded_at: &str,
    ) -> StoreResult<Self> {
        let input: ResolutionRecordingInput = serde_json::from_str(input_json)?;
        let batch = prepare_batch(
            Some(&scope),
            operation_id,
            &input.resolutions,
            actor,
            intent,
            recorded_at,
        )?;
        BindingWire {
            protocol: RESOLUTION_BINDING_PROTOCOL.into(),
            input_hash: crate::stable_hash_hex(input_json),
            input_label: input_label.into(),
            scope,
            batch,
        }
        .try_into()
        .map_err(StoreError::Conflict)
    }
    pub fn scope(&self) -> &ResolutionMemoryScope {
        &self.scope
    }
    pub fn batch(&self) -> &ResolutionMemoryBatch {
        &self.batch
    }
    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
    pub fn input_label(&self) -> &str {
        &self.input_label
    }
}

/// A target bound to one exact input and knowledge operation. Construction is
/// I/O-free; opening the supplied workspace is the authorized host's concern.
pub struct BoundResolutionRecording<B: Branches, C: ContentBlobs> {
    workspace: WorkspaceVcs<B, C>,
    binding: ResolutionRecordingBinding,
    input: ResolutionRecordingInput,
}
impl<B: Branches, C: ContentBlobs> BoundResolutionRecording<B, C> {
    pub fn new(
        workspace: WorkspaceVcs<B, C>,
        binding: ResolutionRecordingBinding,
        input_json: &str,
    ) -> StoreResult<Self> {
        let expected = ResolutionRecordingBinding::prepare(
            input_json,
            binding.input_label(),
            binding.scope().clone(),
            &binding.batch.operation_id,
            &binding.batch.actor,
            &binding.batch.intent,
            &binding.batch.recorded_at,
        )?;
        if binding != expected {
            return Err(StoreError::Conflict(
                "resolution recording input differs from its bound batch".into(),
            ));
        }
        Ok(Self {
            workspace,
            binding,
            input: serde_json::from_str(input_json)?,
        })
    }
    /// Descriptor only; querying this never opens a store or reads knowledge.
    pub fn binding(&self) -> &ResolutionRecordingBinding {
        &self.binding
    }
    /// Invoke only after governed dispatch has retained and authorized binding.
    pub fn record(&mut self) -> StoreResult<ResolutionMemoryReceipt> {
        let batch = &self.binding.batch;
        self.workspace.set_actor(Some(batch.actor.clone()));
        self.workspace.set_intent(Some(batch.intent.clone()));
        self.workspace.record_region_resolutions_in_scope(
            &self.binding.scope,
            &batch.operation_id,
            &self.input.resolutions,
            &batch.recorded_at,
        )
    }
}

/// Read the original batch without decoding an input or querying current memory.
/// Missing is an observation, never permission to retry an uncertain recording.
pub fn read_committed_resolution_recording<B: Branches, C: ContentBlobs>(
    workspace: &WorkspaceVcs<B, C>,
    binding: &ResolutionRecordingBinding,
) -> StoreResult<Option<ResolutionMemoryReceipt>> {
    workspace
        .resolution_receipt(&binding.batch.operation_id)?
        .map(|receipt| receipt.check_retry(&binding.batch))
        .transpose()
}

pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
