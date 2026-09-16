//! Original executor requests survive outcome settlement and later attempts.
use crate::exec_invocation::{Envelope, Invocation};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use whipplescript_store::{
    exec_lifetime::{Track, EVENT_TYPE, PROTOCOL},
    RuntimeStore, StoreError, StoreResult,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tracked {
    protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub input: Value,
    pub invocation: Value,
    pub executor_url: String,
}

/// Tracking is not proof. No run/effect status may hide an outstanding request.
pub fn tracked<S: RuntimeStore>(
    store: &S,
    instance: &str,
) -> StoreResult<BTreeMap<String, Tracked>> {
    let mut result = BTreeMap::new();
    for event in store
        .list_events(instance)?
        .into_iter()
        .filter(|e| e.event_type == EVENT_TYPE)
    {
        let record: Tracked = serde_json::from_str(&event.payload_json)?;
        if record.protocol != PROTOCOL || record.instance_id != instance || event.source != "kernel"
        {
            return Err(StoreError::Conflict(
                "untrusted exec lifetime record".into(),
            ));
        }
        let selected: Invocation = serde_json::from_value(record.invocation["invocation"].clone())?;
        let envelope: Envelope = serde_json::from_value(record.invocation.clone())?;
        envelope.validate(&selected).map_err(StoreError::Conflict)?;
        let input = record.input.to_string();
        let invocation = record.invocation.to_string();
        let track = Track {
            instance_id: instance,
            effect_id: &record.effect_id,
            run_id: &record.run_id,
            input_json: &input,
            invocation_json: &invocation,
            executor_url: &record.executor_url,
        };
        track.payload()?;
        let acknowledged = store.event_by_idempotency_key(instance, &track.key())?;
        if acknowledged.as_ref().map(|ack| ack.event_id.as_str()) != Some(event.event_id.as_str())
            || result.contains_key(&record.run_id)
        {
            return Err(StoreError::Conflict(
                "exec lifetime journal identity changed".into(),
            ));
        }
        result.insert(record.run_id.clone(), record);
    }
    Ok(result)
}

/// Reconstruct original fence intent even after outcome settlement or retry.
pub fn fences<S: RuntimeStore>(
    store: &S,
    instance: &str,
) -> StoreResult<BTreeMap<String, whipplescript_store::exec_lifetime::FenceRecord>> {
    use whipplescript_store::exec_lifetime::{Fence, FenceRecord, FENCE_EVENT};
    let originals = tracked(store, instance)?;
    let mut result = BTreeMap::new();
    for event in store
        .list_events(instance)?
        .into_iter()
        .filter(|event| event.event_type == FENCE_EVENT)
    {
        let record: FenceRecord = serde_json::from_str(&event.payload_json)?;
        let original = originals
            .get(&record.run_id)
            .ok_or_else(|| StoreError::Conflict("exec fence original request is missing".into()))?;
        let request = Fence {
            instance_id: instance,
            run_id: &record.run_id,
            reason: record.reason,
        };
        let tracking = store
            .event_by_idempotency_key(instance, &request.tracking_key())?
            .ok_or_else(|| {
                StoreError::Conflict("exec fence original journal slot is missing".into())
            })?;
        let original_json = Track {
            instance_id: instance,
            effect_id: &original.effect_id,
            run_id: &original.run_id,
            input_json: &original.input.to_string(),
            invocation_json: &original.invocation.to_string(),
            executor_url: &original.executor_url,
        }
        .payload()?;
        let expected = request.payload(&tracking.event_id, EVENT_TYPE, "kernel", &original_json)?;
        request.verify_existing(
            &event.event_type,
            &event.source,
            &event.payload_json,
            &expected,
        )?;
        let acknowledged = store.event_by_idempotency_key(instance, &request.key())?;
        if acknowledged.as_ref().map(|ack| ack.event_id.as_str()) != Some(event.event_id.as_str()) {
            return Err(StoreError::Conflict(
                "exec fence journal identity changed".into(),
            ));
        }
        result.insert(record.run_id.clone(), record);
    }
    Ok(result)
}

pub fn proofs<S: RuntimeStore>(
    store: &S,
    instance: &str,
) -> StoreResult<BTreeMap<String, whipplescript_store::exec_lifetime::ProofRecord>> {
    use whipplescript_store::exec_lifetime::{Journal, Proof, ProofRecord, PROOF_EVENT};
    // Validate original custody and intent, even when all work appears closed.
    let intents = fences(store, instance)?;
    let events = store.list_events(instance)?;
    let mut result = BTreeMap::new();
    for event in events.iter().filter(|e| e.event_type == PROOF_EVENT) {
        let record: ProofRecord = serde_json::from_str(&event.payload_json)?;
        if !intents.contains_key(&record.run_id) {
            return Err(StoreError::Conflict(
                "exec closure intent is missing".into(),
            ));
        }
        let track = events
            .iter()
            .find(|e| e.event_id == record.tracking_event_id)
            .ok_or_else(|| StoreError::Conflict("exec closure tracking event is missing".into()))?;
        let fence = events
            .iter()
            .find(|e| e.event_id == record.fence_event_id)
            .ok_or_else(|| StoreError::Conflict("exec closure fence event is missing".into()))?;
        let closure = serde_json::to_string(&record.closure)?;
        let proof = Proof {
            instance_id: instance,
            run_id: &record.run_id,
            closure_json: &closure,
        };
        let expected = proof.payload(
            Journal {
                event_id: &track.event_id,
                kind: &track.event_type,
                source: &track.source,
                payload: &track.payload_json,
            },
            Journal {
                event_id: &fence.event_id,
                kind: &fence.event_type,
                source: &fence.source,
                payload: &fence.payload_json,
            },
        )?;
        proof.verify_replay(
            &event.event_type,
            &event.source,
            &event.payload_json,
            &expected,
        )?;
        if store
            .event_by_idempotency_key(instance, &proof.key())?
            .as_ref()
            .map(|a| a.event_id.as_str())
            != Some(event.event_id.as_str())
        {
            return Err(StoreError::Conflict(
                "exec closure journal identity changed".into(),
            ));
        }
        result.insert(record.run_id.clone(), record);
    }
    Ok(result)
}

/// Validate durable outcome custody without inferring a workflow terminal.
pub fn outcomes<S: RuntimeStore>(
    store: &S,
    instance: &str,
) -> StoreResult<BTreeMap<String, whipplescript_store::exec_outcome::Record>> {
    use whipplescript_store::{
        exec_lifetime::Journal,
        exec_outcome::{Record, Retention, EVENT_TYPE},
    };
    fences(store, instance)?;
    let events = store.list_events(instance)?;
    let mut result = BTreeMap::new();
    for event in events.iter().filter(|e| e.event_type == EVENT_TYPE) {
        let record: Record = serde_json::from_str(&event.payload_json)?;
        let read = |id: &str| -> StoreResult<Journal<'_>> {
            let e = events.iter().find(|e| e.event_id == id).ok_or_else(|| {
                StoreError::Conflict("exec outcome journal reference is missing".into())
            })?;
            Ok(Journal {
                event_id: &e.event_id,
                kind: &e.event_type,
                source: &e.source,
                payload: &e.payload_json,
            })
        };
        let placement = record.placement.to_string();
        let outcome = serde_json::to_string(&record.outcome)?;
        let request = Retention {
            instance_id: instance,
            run_id: &record.run_id,
            placement_json: &placement,
            outcome_json: &outcome,
        };
        let expected = request.payload(
            read(&record.tracking_event_id)?,
            read(&record.fence_event_id)?,
            record.proof_event_id.as_deref().map(read).transpose()?,
        )?;
        request.verify_replay(
            &event.event_type,
            &event.source,
            &event.payload_json,
            &expected,
        )?;
        if store
            .event_by_idempotency_key(instance, &request.key())?
            .as_ref()
            .map(|e| e.event_id.as_str())
            != Some(event.event_id.as_str())
        {
            return Err(StoreError::Conflict(
                "exec outcome journal identity changed".into(),
            ));
        }
        result.insert(record.run_id.clone(), record);
    }
    Ok(result)
}

/// Host-owned commands only: no caller-selected envelope and no effect readiness
/// filter. A terminal workflow can still owe physical fencing.
pub fn commands<S: RuntimeStore>(store: &S) -> StoreResult<Value> {
    let mut commands = Vec::new();
    for instance in store.list_instances()? {
        let id = &instance.instance_id;
        let original = tracked(store, id)?;
        let closed = proofs(store, id)?;
        let observed = outcomes(store, id)?;
        for (run, intent) in fences(store, id)? {
            if closed.contains_key(&run) && observed.contains_key(&run) {
                continue;
            }
            let track = original.get(&run).ok_or_else(|| {
                StoreError::Conflict("exec fence original request is missing".into())
            })?;
            commands.push(serde_json::json!({"instance_id":id,"run_id":run,"selected":track.invocation["invocation"],
                "envelope":track.invocation,"operation":{"op":"ensure_fence","fence_id":intent.fence_id}}));
        }
    }
    Ok(Value::Array(commands))
}

/// Called only with a response from the private broker, never a public command.
pub fn observe<S: RuntimeStore>(
    store: &mut S,
    instance: &str,
    run: &str,
    response: &str,
) -> StoreResult<bool> {
    if !fences(store, instance)?.contains_key(run) {
        return Err(StoreError::Conflict(
            "exec closure has no requested fence".into(),
        ));
    }
    let originals = tracked(store, instance)?;
    let original = originals
        .get(run)
        .ok_or_else(|| StoreError::Conflict("exec closure original request is missing".into()))?;
    let closure = crate::exec_resolution::closure_json(
        &original.invocation["invocation"].to_string(),
        &original.invocation.to_string(),
        response,
    )
    .map_err(StoreError::Conflict)?;
    let outcome = crate::exec_resolution::outcome_json(
        &original.invocation["invocation"].to_string(),
        &original.invocation.to_string(),
        response,
    )
    .map_err(StoreError::Conflict)?;
    let proof = match &closure {
        Some(closure) => Some(store.retain_exec_fence_proof(
            whipplescript_store::exec_lifetime::Proof {
                instance_id: instance,
                run_id: run,
                closure_json: closure,
            },
        )?),
        None => None,
    };
    if let Some(outcome) = &outcome {
        store.retain_exec_outcome(whipplescript_store::exec_outcome::Retention {
            instance_id: instance,
            run_id: run,
            placement_json: &outcome["placement"].to_string(),
            outcome_json: &outcome["outcome"].to_string(),
        })?;
        // `not_executed` is the validated resolution's own statement that the
        // target never ran -- the one disposition this runtime can prove. It is
        // recorded here because this is where the evidence exists: the host was
        // fenced under retained intent, and the closure is a recorded receipt
        // rather than a caller's assertion. Without it a later retry cannot be
        // admitted at all: `require_proved_absence` refuses a resubmission it
        // cannot prove safe (spec/admission-and-idempotency.md).
        //
        // `uncertain` and `completed` are deliberately NOT recorded here.
        // Uncertain proves nothing, and completed is an application the
        // outcome retention above already states.
        if outcome["outcome"]["state"].as_str() == Some("not_executed") {
            if let (Some(proof), Some(closure)) = (&proof, &closure) {
                record_proved_absence(store, instance, run, proof, closure)?;
            }
        }
    }
    Ok(closure.is_some())
}

/// Record the absence the fence just proved, bound to the SAME dispatch frame
/// the run was admitted under.
///
/// `fold_attempts` refuses evidence whose frame does not equal the attempt's
/// recorded dispatch ("external evidence does not bind a recorded dispatch"),
/// so the frame is read back from the original `effect.run_started` rather
/// than rebuilt here -- a reconstructed frame that differed in any field would
/// be silently unusable.
///
/// A run admitted with no external dispatch has no attempt to bind, and needs
/// no absence proof: there was no target to apply.
fn record_proved_absence<S: RuntimeStore>(
    store: &mut S,
    instance: &str,
    run: &str,
    proof: &whipplescript_store::StoredEvent,
    closure_json: &str,
) -> StoreResult<()> {
    let Some(slot) = store.event_by_idempotency_key(instance, run)? else {
        return Ok(());
    };
    let started = store
        .list_events(instance)?
        .into_iter()
        .find(|event| event.event_id == slot.event_id);
    let Some(started) = started.filter(|event| event.event_type == "effect.run_started") else {
        return Ok(());
    };
    let payload: Value = serde_json::from_str(&started.payload_json)?;
    let Some(dispatch) = payload.get("external_dispatch").cloned() else {
        return Ok(());
    };
    let dispatch: whipplescript_store::effect_recovery::DispatchMarker =
        serde_json::from_value(dispatch)?;
    let evidence = whipplescript_store::effect_recovery::DispositionEvidence {
        frame: dispatch.frame,
        disposition: whipplescript_store::effect_recovery::EvidenceDisposition::NotApplied,
        // The closure receipt IS the evidence: it is the fenced observation
        // that found the run ended without an outcome.
        evidence_ref: proof.event_id.clone(),
        evidence_digest: whipplescript_store::items::sha256_hex(closure_json),
        authority_ref: proof.event_id.clone(),
    };
    // `observe` runs on every reconciliation pass, so this has to be a replay
    // rather than a second commit under the same key.
    let key = format!("exec-absence:{run}");
    if store.event_by_idempotency_key(instance, &key)?.is_some() {
        return Ok(());
    }
    store.append_event(whipplescript_store::NewEvent {
        instance_id: instance,
        event_type: "effect.disposition.recorded",
        payload_json: &serde_json::to_string(&evidence)?,
        source: "kernel",
        causation_id: Some(&proof.event_id),
        correlation_id: Some(run),
        idempotency_key: Some(&key),
    })?;
    Ok(())
}

/// Retirement may remove the journal only after every tracked request is closed.
/// Fencing a completed invocation here is deliberate: the owner is retiring.
pub fn retire<S: RuntimeStore>(store: &mut S) -> StoreResult<()> {
    use whipplescript_store::exec_lifetime::{Fence, FenceReason};
    for instance in store.list_instances()? {
        for run in tracked(store, &instance.instance_id)?.keys() {
            store.ensure_exec_fence(Fence {
                instance_id: &instance.instance_id,
                run_id: run,
                reason: FenceReason::Cancellation,
            })?;
        }
    }
    Ok(())
}

/// Retry intent requests quiescence without granting a replacement attempt.
/// Store admission independently rechecks proof in its own transaction.
pub fn prepare_retry<S: RuntimeStore>(
    store: &mut S,
    instance: &str,
    effect: &str,
) -> StoreResult<()> {
    let retryable = store.list_effects(instance)?.iter().any(|row| {
        row.effect_id == effect
            && row.kind == "exec.command"
            && matches!(row.status.as_str(), "failed" | "timed_out")
    });
    if !retryable {
        return Ok(());
    }
    for (run, original) in tracked(store, instance)? {
        if original.effect_id == effect {
            store.ensure_exec_fence(whipplescript_store::exec_lifetime::Fence {
                instance_id: instance,
                run_id: &run,
                reason: whipplescript_store::exec_lifetime::FenceReason::Retry,
            })?;
        }
    }
    Ok(())
}
