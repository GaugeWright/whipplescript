//! Result lookup folds one recorded prefix. It does not consult mutable
//! projections, resolve an input, run a rule, or contact an external target.
#[cfg(test)]
mod tests;
use std::collections::BTreeSet;

use serde::Deserialize;
use whipplescript_store::effect_recovery::fold_attempts;
use whipplescript_store::event_chain::{fold_owned, OwnedChainEntry};
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::{EventView, RuntimeStore};

use crate::host_facade::{positive_sequence, HostFacadeError};
use crate::host_protocol::action_result::{
    ActionEffectEvidence, ActionEvidenceRef, ActionInstanceStatus, ActionResultSnapshot,
    ActionTerminalEvidence, ActionWorkflowStatus, ReadActionResult, VerifiedResultRead,
    ACTION_RESULT_PROTOCOL,
};
use crate::host_protocol::{PinnedPosition, ProtocolError};
use crate::RuntimeKernel;

impl<S: RuntimeStore + LogAppend> RuntimeKernel<S> {
    pub(crate) fn read_recorded_action_result(
        &self,
        verified: &VerifiedResultRead,
    ) -> Result<ActionResultSnapshot, HostFacadeError> {
        let request = verified.request();
        let prefix = self
            .store()
            .chain_prefix(&request.admission.instance_ref)
            .map_err(HostFacadeError::Store)?;
        snapshot(request, prefix)
    }
}

#[derive(Deserialize)]
struct RecordedRule {
    effects: Vec<RecordedEffect>,
}

#[derive(Deserialize)]
struct RecordedEffect {
    effect_id: String,
}

#[derive(Deserialize)]
struct RecordedTransition {
    status: ActionInstanceStatus,
}

fn snapshot(
    request: &ReadActionResult,
    mut prefix: Vec<OwnedChainEntry>,
) -> Result<ActionResultSnapshot, HostFacadeError> {
    let instance = &request.admission.instance_ref;
    if let Some(through) = &request.through {
        let end = i64::try_from(through.sequence).unwrap_or(i64::MAX);
        // Preserve malformed earlier coordinates so the prefix validator
        // refuses them; filtering is only an upper bound on historical reads.
        prefix.retain(|event| event.sequence <= end);
    }
    let observed_at = pin(instance, &prefix)?;
    if request
        .through
        .as_ref()
        .is_some_and(|through| *through != observed_at)
    {
        return Err(ProtocolError::Mismatch("result requested prefix").into());
    }
    let (command, admission_index) = crate::host_action::recorded_action_command(
        &request.admission,
        &request.issuer,
        &request.scope,
        &prefix,
    )?;
    let admitted = &prefix[admission_index];

    let mut terminal = None;
    let mut instance_status = ActionInstanceStatus::Running;
    let mut status_evidence = ActionEvidenceRef {
        event_id: admitted.event_id.clone(),
        sequence: positive_sequence(admitted.sequence)?,
        kind: admitted.event_type.clone(),
    };
    let mut effect_ids = BTreeSet::new();
    let mut evidence = Vec::with_capacity(prefix.len());
    let mut events = Vec::with_capacity(prefix.len());
    for (index, event) in prefix.iter().enumerate() {
        let reference = ActionEvidenceRef {
            event_id: event.event_id.clone(),
            sequence: positive_sequence(event.sequence)?,
            kind: event.event_type.clone(),
        };
        if event.source.as_deref() == Some("kernel") {
            if event.event_type == "instance.transitioned" {
                let transition: RecordedTransition =
                    serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
                instance_status = transition.status;
                status_evidence = reference.clone();
            }
            if event.event_type == "rule.committed" {
                let rule: RecordedRule =
                    serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
                effect_ids.extend(rule.effects.into_iter().map(|effect| effect.effect_id));
            }
            if matches!(
                event.event_type.as_str(),
                "effect.run_started" | "effect.terminal" | "lease.expired"
            ) {
                let effect: RecordedEffect =
                    serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
                effect_ids.insert(effect.effect_id);
            }
            let status = match event.event_type.as_str() {
                "workflow.completed" => Some(ActionWorkflowStatus::Completed),
                "workflow.failed" => Some(ActionWorkflowStatus::Failed),
                _ => None,
            };
            if let Some(status) = status {
                if terminal.is_some() {
                    return Err(
                        ProtocolError::Mismatch("result has multiple workflow terminals").into(),
                    );
                }
                instance_status = match status {
                    ActionWorkflowStatus::Completed => ActionInstanceStatus::Completed,
                    ActionWorkflowStatus::Failed => ActionInstanceStatus::Failed,
                };
                status_evidence = reference.clone();
                terminal = Some(ActionTerminalEvidence {
                    status,
                    recorded_at: pin(instance, &prefix[..=index])?,
                    evidence: reference.clone(),
                });
            }
        }
        evidence.push(reference);
        events.push(EventView {
            event_id: event.event_id.clone(),
            sequence: event.sequence,
            event_type: event.event_type.clone(),
            payload_json: event.payload_json.clone(),
            source: event.source.clone().unwrap_or_default(),
            occurred_at: event.occurred_at.clone(),
        });
    }
    let effects = effect_ids
        .into_iter()
        .map(|effect_id| {
            let attempts =
                fold_attempts(instance, &effect_id, &events).map_err(HostFacadeError::Store)?;
            Ok(ActionEffectEvidence {
                effect_id,
                attempts,
            })
        })
        .collect::<Result<Vec<_>, HostFacadeError>>()?;
    Ok(ActionResultSnapshot {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        admission: request.admission.clone(),
        command,
        read_policy: request.policy.clone(),
        evidence_handle: request.evidence_handle.clone(),
        evidence_label_ref: request.evidence_label_ref.clone(),
        observed_at,
        instance_status,
        status_evidence,
        terminal,
        effects,
        evidence,
    })
}

fn pin(instance: &str, prefix: &[OwnedChainEntry]) -> Result<PinnedPosition, HostFacadeError> {
    if prefix.is_empty()
        || !prefix.iter().enumerate().all(|(index, event)| {
            i64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                == Some(event.sequence)
        })
    {
        return Err(ProtocolError::Mismatch("result complete recorded prefix").into());
    }
    let head = fold_owned(instance, prefix);
    Ok(PinnedPosition {
        instance_ref: instance.into(),
        sequence: positive_sequence(head.sequence.unwrap_or_default())?,
        head_digest: head.digest,
    })
}
