//! Native norm execution closes physical custody before workflow settlement.
use super::*;
use crate::native_controller::{Command, Identity};
use serde_json::Value;
use whipplescript_kernel::{
    exec_lifetime, exec_outcome_settlement, norm_runner::PythonCallMethod, RuntimeKernel,
};
use whipplescript_store::{ClaimableEffect, StoredEvent};

#[derive(Debug)]
pub struct NativeNormProgress {
    pub closed: bool,
    pub cleanup_pending: bool,
    pub terminal_events: Vec<StoredEvent>,
}

#[derive(Debug, Default)]
pub struct NativeNormRecovery {
    pub terminal_events: Vec<StoredEvent>,
    pub pending: usize,
}

/// Original admissions remain visible after settlement; current run metadata
/// can legitimately have been replaced with terminal evidence.
pub fn native_norm_runs(store: &SqliteStore, instance: &str) -> StoreResult<Vec<String>> {
    let mut runs = std::collections::BTreeSet::new();
    for event in store.list_events(instance)? {
        if event.event_type != "effect.run_started" {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if payload["metadata"]["executor_transport"] == "native-managed" {
            runs.insert(
                payload["run_id"]
                    .as_str()
                    .ok_or_else(|| {
                        StoreError::Conflict("native norm admission has no run identity".into())
                    })?
                    .to_owned(),
            );
        }
    }
    for run in store.list_runs(instance)? {
        let metadata: Value = serde_json::from_str(&run.metadata_json)?;
        if metadata["executor_transport"] == "native-managed" {
            runs.insert(run.run_id);
        }
    }
    // A damaged admission cannot disappear merely because its tracking remains.
    for (run, original) in exec_lifetime::tracked(store, instance)? {
        if original.executor_url == "whip-executor://native/exec"
            && original.input.get("norm_intent").is_some()
        {
            runs.insert(run);
        }
    }
    Ok(runs.into_iter().collect())
}

impl Docker {
    pub fn recover_norm_instance(
        &mut self,
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        now: &str,
        fence: bool,
    ) -> StoreResult<NativeNormRecovery> {
        let runs = native_norm_runs(kernel.store(), instance)?;
        if runs.is_empty() {
            return Ok(NativeNormRecovery::default());
        }
        norm_admission::lease_expiry(now)?;
        let tracked = exec_lifetime::tracked(kernel.store(), instance)?;
        for run in &runs {
            if !tracked.contains_key(run) {
                NativeNormAdmission::restore_tracking(kernel, instance, run)?;
            }
        }
        kernel.expire_leases(instance, now)?;
        let mut report = NativeNormRecovery::default();
        for run in runs {
            let (binding, identity) = original_binding(kernel.store(), instance, &run)?;
            let active = kernel
                .store()
                .get_instance(instance)?
                .is_some_and(|row| row.status == "running")
                && kernel
                    .store()
                    .list_runs(instance)?
                    .iter()
                    .any(|row| row.run_id == run && row.status == "running")
                && kernel.store().list_effects(instance)?.iter().any(|row| {
                    row.effect_id == identity.selected.effect_id && row.status == "running"
                })
                && kernel
                    .store()
                    .effect_attempt_admission(instance, &identity.selected.effect_id)?
                    == identity.selected.attempt_admission_event_id;
            if fence || !active {
                kernel.store_mut().ensure_exec_fence(Fence {
                    instance_id: instance,
                    run_id: &run,
                    reason: FenceReason::Recovery,
                })?;
            }
            let progress = if exec_lifetime::fences(kernel.store(), instance)?.contains_key(&run) {
                self.poll_norm(kernel, instance, &run)?
            } else {
                // Resume only the original, current admission. Its external
                // controller decides whether startup or delivery is still due;
                // a live pending call remains untouched by the driver.
                let effect = NativeNormAdmission::restore_tracking(kernel, instance, &run)?;
                self.execute_norm_at(kernel, instance, &effect, &binding, now)?
            };
            report.pending += usize::from(!progress.closed || progress.cleanup_pending);
            report.terminal_events.extend(progress.terminal_events);
        }
        Ok(report)
    }

    pub fn execute_norm(
        &mut self,
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        effect: &ClaimableEffect,
        installed: &NativeRuntimeImage,
    ) -> StoreResult<NativeNormProgress> {
        let now = chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.execute_norm_at(kernel, instance, effect, installed, &now)
    }

    pub fn execute_norm_at(
        &mut self,
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        effect: &ClaimableEffect,
        installed: &NativeRuntimeImage,
        now: &str,
    ) -> StoreResult<NativeNormProgress> {
        let admission = NativeNormAdmission::admit_at(kernel, instance, effect, installed, now)?;
        let run = admission.handoff.run_id();
        let binding = &admission.binding;
        let identity: Identity = serde_json::from_value(admission.handoff.command())?;
        if let Some(candidate) = &admission.candidate {
            let mut held = self.prepare_managed(
                &binding.daemon_id,
                &binding.base_image,
                &identity,
                candidate,
            )?;
            if held.response["action"]["action"] == "absent" && held.state.container_id.is_some() {
                held = self.deliver_managed(&binding.daemon_id, &binding.base_image, &identity)?;
            }
            if matches!(
                held.response["action"]["action"].as_str(),
                Some("absent" | "pending")
            ) {
                // A concurrent owner may still be executing. Only retained
                // deadline/cancellation/recovery intent may fence that work.
                return Ok(NativeNormProgress {
                    closed: false,
                    cleanup_pending: held.state.owner.is_some()
                        && held.state.container_id.is_none(),
                    terminal_events: vec![],
                });
            }
            kernel.store_mut().ensure_exec_fence(Fence {
                instance_id: instance,
                run_id: &run,
                reason: FenceReason::Recovery,
            })?;
        }
        self.reconcile_norm(kernel, instance, &run)
    }

    /// Observe original execution without preparing, starting, or delivering it.
    /// Retained fence intent also drives cleanup after workflow settlement.
    pub fn poll_norm(
        &mut self,
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        run: &str,
    ) -> StoreResult<NativeNormProgress> {
        let (binding, identity) = original_binding(kernel.store(), instance, run)?;
        if !exec_lifetime::fences(kernel.store(), instance)?.contains_key(run) {
            let held = self.controller(
                &binding.daemon_id,
                &binding.base_image,
                &identity,
                Command::Read,
            )?;
            if matches!(
                held.response["action"]["action"].as_str(),
                Some("absent" | "pending")
            ) {
                return Ok(NativeNormProgress {
                    closed: false,
                    cleanup_pending: held.state.owner.is_some()
                        && held.state.container_id.is_none(),
                    terminal_events: vec![],
                });
            }
            kernel.store_mut().ensure_exec_fence(Fence {
                instance_id: instance,
                run_id: run,
                reason: FenceReason::Recovery,
            })?;
        }
        self.reconcile_norm(kernel, instance, run)
    }

    /// Continues original cleanup, including after a workflow has settled.
    /// The caller must retain fence intent first; this is never redispatch.
    pub fn reconcile_norm(
        &mut self,
        kernel: &mut RuntimeKernel<SqliteStore>,
        instance: &str,
        run: &str,
    ) -> StoreResult<NativeNormProgress> {
        let (binding, _) = original_binding(kernel.store(), instance, run)?;
        let state = self.reconcile_managed(
            kernel.store_mut(),
            &binding.daemon_id,
            &binding.base_image,
            instance,
            run,
        )?;
        let terminal_events = if state.closed {
            exec_outcome_settlement::settle_instance(kernel, instance)?
        } else {
            vec![]
        };
        Ok(NativeNormProgress {
            closed: state.closed,
            cleanup_pending: state.cleanup_pending,
            terminal_events,
        })
    }
}

fn original_binding(
    store: &SqliteStore,
    instance: &str,
    run: &str,
) -> StoreResult<(NativeRuntimeImage, Identity)> {
    let originals = exec_lifetime::tracked(store, instance)?;
    let original = originals.get(run).ok_or_else(|| {
        StoreError::Conflict("native norm recovery requires original tracking".into())
    })?;
    let start = store
        .event_by_idempotency_key(instance, run)?
        .ok_or_else(|| {
            StoreError::Conflict("native norm original admission slot is missing".into())
        })?;
    let events = store.list_events(instance)?;
    let event = events
        .iter()
        .find(|event| event.event_id == start.event_id)
        .ok_or_else(|| {
            StoreError::Conflict("native norm original admission event is missing".into())
        })?;
    let payload: Value = serde_json::from_str(&event.payload_json)?;
    if event.event_type != "effect.run_started"
        || event.source != "kernel"
        || payload["run_id"] != run
        || payload["effect_id"] != original.effect_id
        || payload["metadata"]["executor_invocation"] != original.invocation
    {
        return Err(StoreError::Conflict(
            "native norm original admission differs from its tracking".into(),
        ));
    }
    let metadata = &payload["metadata"];
    if metadata["executor_transport"] != "native-managed" {
        return Err(StoreError::Conflict(
            "native norm recovery requires its managed binding".into(),
        ));
    }
    let binding: NativeRuntimeImage = serde_json::from_value(metadata["native_runtime"].clone())?;
    let method: PythonCallMethod = serde_json::from_str(
        original.input["stdin"]["method_definition_json"]
            .as_str()
            .unwrap_or_default(),
    )?;
    binding.validate_for(&method.runtime)?;
    if original.executor_url != "whip-executor://native/exec" {
        return Err(StoreError::Conflict(
            "native norm polling cannot target another executor".into(),
        ));
    }
    let identity = Identity {
        selected: serde_json::from_value(original.invocation["invocation"].clone())?,
        envelope: serde_json::from_value(original.invocation.clone())?,
    };
    Ok((binding, identity))
}
